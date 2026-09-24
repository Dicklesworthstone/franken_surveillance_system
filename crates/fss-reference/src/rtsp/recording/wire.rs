#![forbid(unsafe_code)]

use super::*;
use fss_container::NalTarget;
use fss_core::{CanonicalDecoder, CanonicalEncoder};
use fss_packet::{NalSourceSpan, avc::AvcBoundary};

const INDEX_SCHEMA: &str = "fss.recording_window.index.v1";
const SOURCE_SCHEMA: &str = "fss.recording_window.source.v1";

pub(super) fn encode_packets(packets: &[RecordingPacket<'_>]) -> Result<Vec<u8>> {
    if packets.is_empty() || packets.len() > MAX_RECORDING_PACKETS {
        return Err(RecordingError::Limit);
    }
    let mut size = 64_usize;
    let mut last = None;
    for p in packets {
        if p.bytes.len() > 65_535 || last.is_some_and(|seq| p.sequence <= seq) {
            return Err(RecordingError::Source);
        }
        size = size
            .checked_add(24)
            .and_then(|n| n.checked_add(p.bytes.len()))
            .ok_or(RecordingError::Limit)?;
        if size > MAX_RECORDING_BYTES {
            return Err(RecordingError::Limit);
        }
        last = Some(p.sequence);
    }
    let mut e = CanonicalEncoder::new();
    e.text(SOURCE_SCHEMA);
    e.u64(packets.len() as u64);
    for p in packets {
        e.u64(p.sequence);
        e.u64(p.received_ns);
        e.bytes(p.bytes);
    }
    e.finish_checked().map_err(|_| RecordingError::Malformed)
}

pub(super) fn decode_packets(bytes: &[u8]) -> Result<Vec<RecordingPacket<'_>>> {
    if bytes.len() > MAX_RECORDING_BYTES {
        return Err(RecordingError::Limit);
    }
    let mut d = Decoder::new(bytes);
    if d.text()? != SOURCE_SCHEMA {
        return Err(RecordingError::Malformed);
    }
    let count = d.count(MAX_RECORDING_PACKETS)?;
    if count == 0 {
        return Err(RecordingError::Source);
    }
    let mut packets = bounded_vec(count, MAX_RECORDING_PACKETS)?;
    let mut previous = None;
    for _ in 0..count {
        let sequence = d.u64()?;
        let received_ns = d.u64()?;
        let data = d.0.bytes().map_err(|_| RecordingError::Malformed)?;
        if data.len() > 65_535 || previous.is_some_and(|last| sequence <= last) {
            return Err(RecordingError::Source);
        }
        packets.push(RecordingPacket {
            sequence,
            received_ns,
            bytes: data,
        });
        previous = Some(sequence);
    }
    d.end()?;
    Ok(packets)
}

pub(super) fn encode_index(index: &Index) -> Result<Vec<u8>> {
    if index.samples.len() > MAX_RECORDING_SAMPLES || index.mappings.len() > MAX_RECORDING_MAPPINGS
    {
        return Err(RecordingError::Limit);
    }
    let spans = index
        .mappings
        .iter()
        .try_fold(0_usize, |s, m| s.checked_add(m.sources.len()))
        .ok_or(RecordingError::Limit)?;
    if spans > MAX_RECORDING_MAPPINGS {
        return Err(RecordingError::Limit);
    }
    let mut e = CanonicalEncoder::new();
    e.text(INDEX_SCHEMA);
    e.text(index.scope.sensor.as_str());
    e.text(index.scope.stream.as_str());
    e.u64(index.scope.generation);
    e.digest(index.scope.anchor);
    e.digest(index.scope.receive_clock);
    e.u32(index.ssrc);
    e.u32(u32::from(index.payload_type));
    e.u32(index.time_scale);
    e.digest(index.source);
    e.digest(index.initialization);
    e.digest(index.media);
    range(&mut e, &index.sps);
    range(&mut e, &index.pps);
    e.u64(index.samples.len() as u64);
    for s in &index.samples {
        range(&mut e, &s.range);
        e.u64(s.decode_time);
        e.u64(s.presentation_time);
        e.u32(s.duration);
        e.u32(s.rtp_timestamp);
        e.bool(s.idr);
        e.u64(boundary_code(s.boundary));
        range(&mut e, &s.mappings);
    }
    e.u64(index.mappings.len() as u64);
    for m in &index.mappings {
        e.u64(m.sample as u64);
        e.u64(m.nal as u64);
        match &m.target {
            NalTarget::Initialization(r) => {
                e.bool(false);
                range(&mut e, r);
            }
            NalTarget::Media(r) => {
                e.bool(true);
                range(&mut e, r);
            }
        }
        e.u64(m.sources.len() as u64);
        for s in &m.sources {
            e.u64(s.sequence);
            range(&mut e, &s.wire_range);
            range(&mut e, &s.nal_range);
            e.bool(s.fragment_header_range.is_some());
            if let Some(r) = &s.fragment_header_range {
                range(&mut e, r);
            }
        }
    }
    e.finish_checked().map_err(|_| RecordingError::Malformed)
}

pub(super) fn decode_index(bytes: &[u8]) -> Result<Index> {
    // Even maximal fixed counts cannot produce more than this metadata budget.
    if bytes.len() > 2 * 1024 * 1024 {
        return Err(RecordingError::Limit);
    }
    let mut d = Decoder::new(bytes);
    if d.text()? != INDEX_SCHEMA {
        return Err(RecordingError::Malformed);
    }
    let sensor = SensorId::parse(d.text()?).map_err(|_| RecordingError::Scope)?;
    let stream = StreamId::parse(d.text()?).map_err(|_| RecordingError::Scope)?;
    let generation = d.u64()?;
    let anchor = d.digest()?;
    let receive_clock = d.digest()?;
    let ssrc = d.u32()?;
    let payload_type = u8::try_from(d.u32()?).map_err(|_| RecordingError::Scope)?;
    if payload_type > 127 {
        return Err(RecordingError::Scope);
    }
    let time_scale = d.u32()?;
    let source = d.digest()?;
    let initialization = d.digest()?;
    let media = d.digest()?;
    let sps = d.range()?;
    let pps = d.range()?;
    let count = d.count(MAX_RECORDING_SAMPLES)?;
    if count == 0 {
        return Err(RecordingError::Malformed);
    }
    let mut samples = bounded_vec(count, MAX_RECORDING_SAMPLES)?;
    for _ in 0..count {
        samples.push(SampleMapping {
            range: d.range()?,
            decode_time: d.u64()?,
            presentation_time: d.u64()?,
            duration: d.u32()?,
            rtp_timestamp: d.u32()?,
            idr: d.boolean()?,
            boundary: decode_boundary(d.u64()?)?,
            mappings: d.range()?,
        });
    }
    let count = d.count(MAX_RECORDING_MAPPINGS)?;
    let mut mappings = bounded_vec(count, MAX_RECORDING_MAPPINGS)?;
    let mut spans_left = MAX_RECORDING_MAPPINGS;
    for _ in 0..count {
        let sample = d.count(MAX_RECORDING_SAMPLES)?;
        let nal = d.count(MAX_RECORDING_MAPPINGS)?;
        let in_media = d.boolean()?;
        let r = d.range()?;
        let target = if in_media {
            NalTarget::Media(r)
        } else {
            NalTarget::Initialization(r)
        };
        let count = d.count(spans_left)?;
        if count == 0 {
            return Err(RecordingError::Source);
        }
        spans_left -= count;
        let mut sources = bounded_vec(count, MAX_RECORDING_MAPPINGS)?;
        for _ in 0..count {
            sources.push(NalSourceSpan {
                sequence: d.u64()?,
                wire_range: d.range()?,
                nal_range: d.range()?,
                fragment_header_range: if d.boolean()? { Some(d.range()?) } else { None },
            });
        }
        mappings.push(NalMapping {
            sample,
            nal,
            target,
            sources,
        });
    }
    d.end()?;
    Ok(Index {
        scope: RecordingScope {
            sensor,
            stream,
            generation,
            anchor,
            receive_clock,
        },
        ssrc,
        payload_type,
        time_scale,
        source,
        initialization,
        media,
        sps,
        pps,
        samples,
        mappings,
    })
}

fn range(e: &mut CanonicalEncoder, r: &Range<usize>) {
    e.u64(r.start as u64);
    e.u64(r.end as u64);
}
fn boundary_code(b: AvcBoundary) -> u64 {
    match b {
        AvcBoundary::NextPrimaryPicture => 1,
        AvcBoundary::NextAccessUnitPrefix => 2,
        AvcBoundary::RtpMarker => 3,
        AvcBoundary::EndOfSequence => 4,
        AvcBoundary::EndOfStream => 5,
        AvcBoundary::EndOfInputUnverified => 6,
    }
}
fn decode_boundary(code: u64) -> Result<AvcBoundary> {
    match code {
        1 => Ok(AvcBoundary::NextPrimaryPicture),
        2 => Ok(AvcBoundary::NextAccessUnitPrefix),
        3 => Ok(AvcBoundary::RtpMarker),
        4 => Ok(AvcBoundary::EndOfSequence),
        5 => Ok(AvcBoundary::EndOfStream),
        6 => Ok(AvcBoundary::EndOfInputUnverified),
        _ => Err(RecordingError::Malformed),
    }
}
struct Decoder<'a>(CanonicalDecoder<'a>);
impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self(CanonicalDecoder::new(bytes))
    }
    fn text(&mut self) -> Result<&'a str> {
        self.0.text().map_err(|_| RecordingError::Malformed)
    }
    fn u32(&mut self) -> Result<u32> {
        self.0.u32().map_err(|_| RecordingError::Malformed)
    }
    fn u64(&mut self) -> Result<u64> {
        self.0.u64().map_err(|_| RecordingError::Malformed)
    }
    fn boolean(&mut self) -> Result<bool> {
        self.0.bool().map_err(|_| RecordingError::Malformed)
    }
    fn digest(&mut self) -> Result<ContentDigest> {
        self.0.digest().map_err(|_| RecordingError::Malformed)
    }
    fn count(&mut self, max: usize) -> Result<usize> {
        let n = usize::try_from(self.u64()?).map_err(|_| RecordingError::Limit)?;
        if n > max {
            return Err(RecordingError::Limit);
        }
        Ok(n)
    }
    fn range(&mut self) -> Result<Range<usize>> {
        let start = self.count(MAX_RECORDING_BYTES)?;
        let end = self.count(MAX_RECORDING_BYTES)?;
        if start > end {
            return Err(RecordingError::Malformed);
        }
        Ok(start..end)
    }
    fn end(&mut self) -> Result<()> {
        self.0
            .ensure_finished()
            .map_err(|_| RecordingError::Malformed)
    }
}
