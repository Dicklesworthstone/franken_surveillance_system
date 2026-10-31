#![forbid(unsafe_code)]
//! Exact admitted-source links; no packet cache, RTP sequence aliasing or guessed clocks.

use super::*;
use crate::rtsp::datagram_archive::{DatagramRecord, DatagramScope};
use fss_packet::jpeg::JpegFrame;
use std::ops::Range;

/// One actual admitted observation, distinct from equal retransmissions in the archive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JpegSourceDependency {
    /// Extended RTP sequence in the source scope's exact ingress, generation and SSRC.
    pub sequence: u64,
    /// Original durable root, payload identity, arrival ordinal, channel and receive time.
    pub record: DatagramRecord,
}

/// Opaque commitment over the complete reconstruction and its exact original dependencies.
///
/// This is evidence of this verified replay, not authority or a perpetual custody claim.
/// The complete frame still owns its copied-byte, interpreted-header and generated ranges.
/// Earlier cached quantizer definitions are included even when outside the frame interval.
#[derive(Debug)]
pub struct JpegFrameProvenance {
    source: DatagramPin,
    interpretation: ContentDigest,
    encoded_digest: ContentDigest,
    digest: ContentDigest,
    receive_clock: ContentDigest,
    dependencies: Vec<JpegSourceDependency>,
}

impl JpegFrameProvenance {
    /// Complete independently selected prefix, including original RTCP and duplicates.
    pub fn source(&self) -> DatagramPin {
        self.source
    }
    /// Exact source, negotiated profile, bounds and deterministic scheduling policy.
    pub fn interpretation(&self) -> ContentDigest {
        self.interpretation
    }
    /// Exact derived JPEG bytes; this is the input digest for native pixel decoding.
    pub fn encoded_digest(&self) -> ContentDigest {
        self.encoded_digest
    }
    /// Canonical source-map identity, separate from encoded-image and pixel identities.
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }
    /// Owner-selected historical receive-clock identity, never current storage time.
    pub fn receive_clock(&self) -> ContentDigest {
        self.receive_clock
    }
    /// Unknown: neither RTP timestamps, arrival time nor uncalibrated RTCP supplies this.
    pub fn capture_clock(&self) -> Option<ContentDigest> {
        None
    }
    /// Unique actual originals in increasing extended-sequence order.
    pub fn dependencies(&self) -> &[JpegSourceDependency] {
        &self.dependencies
    }
}

/// Bounded metadata only. Pending entries cover the transport queue; delivered entries
/// are sorted by the native receiver's strictly increasing sequence and searched in O(log n).
#[derive(Debug)]
pub(super) struct SourceIndex {
    pending: Vec<JpegSourceDependency>,
    delivered: Vec<JpegSourceDependency>,
    max_pending: usize,
    max_sources: usize,
}

impl SourceIndex {
    pub(super) fn new(max_sources: usize, max_pending: usize) -> Result<Self> {
        let max_pending = max_pending.min(max_sources);
        let mut pending = Vec::new();
        let mut delivered = Vec::new();
        pending
            .try_reserve_exact(max_pending)
            .map_err(|_| DatagramArchiveError::Limit)?;
        delivered
            .try_reserve_exact(max_sources)
            .map_err(|_| DatagramArchiveError::Limit)?;
        Ok(Self {
            pending,
            delivered,
            max_pending,
            max_sources,
        })
    }

    /// Attach provenance only after the receiver produced an owned event. The caller
    /// retains that event in a failure retirement if allocation or binding is refused.
    pub(super) fn bind(
        &mut self,
        step: &mut JpegReplayStep,
        scope: &DatagramScope,
        source_pin: DatagramPin,
        interpretation: ContentDigest,
    ) -> Result<()> {
        match step {
            JpegReplayStep::Rtp {
                source, admission, ..
            } if admission.transport.disposition == ReorderDisposition::Buffered => {
                let sequence = admission
                    .transport
                    .sequence
                    .extended_sequence
                    .ok_or(JpegReplayError::Invariant)?;
                let at = self
                    .pending
                    .binary_search_by_key(&sequence, |entry| entry.sequence)
                    .err()
                    .ok_or(JpegReplayError::Invariant)?;
                if self.pending.len() >= self.max_pending {
                    return Err(JpegReplayError::Invariant);
                }
                self.pending.insert(
                    at,
                    JpegSourceDependency {
                        sequence,
                        record: source.record(),
                    },
                );
            }
            JpegReplayStep::Media {
                event:
                    JpegReceivePoll::Packet {
                        source,
                        reconstruction,
                    },
                provenance,
                ..
            } => {
                let sequence = source.sequence();
                let at = self
                    .pending
                    .binary_search_by_key(&sequence, |entry| entry.sequence)
                    .map_err(|_| JpegReplayError::Invariant)?;
                let dependency = self.pending[at];
                if source.key() != scope.binding.key()
                    || source.received_ns() != dependency.record.received_ns
                    || source.bytes().len() != dependency.record.payload_bytes
                    || ContentDigest::sha256(source.bytes()) != dependency.record.payload_digest
                    || self.delivered.len() >= self.max_sources
                    || self
                        .delivered
                        .last()
                        .is_some_and(|previous| previous.sequence >= sequence)
                {
                    return Err(JpegReplayError::Invariant);
                }
                self.pending.remove(at);
                self.delivered.push(dependency);
                if let Ok(output) = reconstruction
                    && let Some(frame) = output.frame.as_deref()
                {
                    *provenance = Some(self.frame(frame, scope, source_pin, interpretation)?);
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn dependency(&self, sequence: u64) -> Result<JpegSourceDependency> {
        self.delivered
            .binary_search_by_key(&sequence, |entry| entry.sequence)
            .ok()
            .and_then(|at| self.delivered.get(at).copied())
            .ok_or(JpegReplayError::Invariant)
    }

    fn frame(
        &self,
        frame: &JpegFrame,
        scope: &DatagramScope,
        source: DatagramPin,
        interpretation: ContentDigest,
    ) -> Result<JpegFrameProvenance> {
        if frame.key() != scope.binding.key() {
            return Err(JpegReplayError::Invariant);
        }
        let count = frame
            .source_spans()
            .len()
            .checked_add(frame.header_sources().len())
            .ok_or(JpegReplayError::Invariant)?;
        let mut sequences = Vec::new();
        sequences
            .try_reserve_exact(count)
            .map_err(|_| DatagramArchiveError::Limit)?;
        for span in frame.source_spans() {
            let record = self.dependency(span.sequence)?.record;
            validate_range(&span.wire_range, record.payload_bytes)?;
            validate_range(&span.jpeg_range, frame.bytes().len())?;
            if span.wire_range.len() != span.jpeg_range.len() {
                return Err(JpegReplayError::Invariant);
            }
            sequences.push(span.sequence);
        }
        for header in frame.header_sources() {
            let record = self.dependency(header.sequence)?.record;
            validate_range(&header.wire_range, record.payload_bytes)?;
            sequences.push(header.sequence);
        }
        for range in frame.generated_ranges() {
            validate_range(range, frame.bytes().len())?;
        }
        sequences.sort_unstable();
        sequences.dedup();
        let mut dependencies = Vec::new();
        dependencies
            .try_reserve_exact(sequences.len())
            .map_err(|_| DatagramArchiveError::Limit)?;
        for sequence in sequences {
            let dependency = self.dependency(sequence)?;
            if dependency.record.pin.scope != source.scope
                || dependency.record.pin.datagrams > source.datagrams
                || dependency.record.channel != scope.channels.0
            {
                return Err(JpegReplayError::Invariant);
            }
            dependencies.push(dependency);
        }
        let encoded_digest = ContentDigest::sha256(frame.bytes());
        let digest = digest(
            frame,
            source,
            interpretation,
            encoded_digest,
            scope.receive_clock,
            &dependencies,
        )?;
        Ok(JpegFrameProvenance {
            source,
            interpretation,
            encoded_digest,
            digest,
            receive_clock: scope.receive_clock,
            dependencies,
        })
    }
}

fn validate_range(range: &Range<usize>, limit: usize) -> Result<()> {
    if range.start >= range.end || range.end > limit {
        return Err(JpegReplayError::Invariant);
    }
    Ok(())
}

fn pin(encoder: &mut CanonicalEncoder, value: DatagramPin) {
    encoder.digest(value.scope);
    encoder.digest(value.head);
    encoder.u64(value.datagrams);
    encoder.u64(value.payload_bytes);
}

fn range(encoder: &mut CanonicalEncoder, value: &Range<usize>) -> Result<()> {
    encoder.u64(u64::try_from(value.start).map_err(|_| JpegReplayError::Invariant)?);
    encoder.u64(u64::try_from(value.end).map_err(|_| JpegReplayError::Invariant)?);
    Ok(())
}

fn digest(
    frame: &JpegFrame,
    source: DatagramPin,
    interpretation: ContentDigest,
    encoded_digest: ContentDigest,
    receive_clock: ContentDigest,
    dependencies: &[JpegSourceDependency],
) -> Result<ContentDigest> {
    let mut e = CanonicalEncoder::new();
    e.text("fss.rtsp_datagram_jpeg_frame_provenance.v1");
    pin(&mut e, source);
    e.digest(interpretation);
    e.digest(encoded_digest);
    e.digest(receive_clock);
    e.text("capture-clock-unknown");
    let key = frame.key();
    e.u64((key.ingress >> 64) as u64);
    e.u64(key.ingress as u64);
    e.u64(key.generation);
    e.u32(key.ssrc);
    e.u32(frame.timestamp());
    for dimension in frame.dimensions() {
        e.u32(u32::from(dimension));
    }
    e.tag(frame.jpeg_type());
    e.tag(frame.quality());
    e.u32(u32::from(frame.restart_interval().unwrap_or(0)));
    for sequence in frame.sequence_interval() {
        e.u64(sequence);
    }
    e.u64(frame.fragments() as u64);
    e.u64(dependencies.len() as u64);
    for dependency in dependencies {
        e.u64(dependency.sequence);
        let record = dependency.record;
        pin(&mut e, record.prior);
        pin(&mut e, record.pin);
        e.tag(record.channel);
        e.u64(record.received_ns);
        e.digest(record.payload_digest);
        e.u64(record.payload_bytes as u64);
    }
    e.u64(frame.source_spans().len() as u64);
    for span in frame.source_spans() {
        e.u64(span.sequence);
        range(&mut e, &span.wire_range)?;
        range(&mut e, &span.jpeg_range)?;
    }
    e.u64(frame.header_sources().len() as u64);
    for header in frame.header_sources() {
        e.u64(header.sequence);
        range(&mut e, &header.wire_range)?;
    }
    e.u64(frame.generated_ranges().len() as u64);
    for generated in frame.generated_ranges() {
        range(&mut e, generated)?;
    }
    let bytes = e.finish_checked().map_err(|_| JpegReplayError::Invariant)?;
    ContentDigest::try_sha256(&bytes).map_err(|_| JpegReplayError::Invariant)
}
