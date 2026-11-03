#![forbid(unsafe_code)]
//! Versioned exact request; replay semantics and every independent bound are committed.

use super::*;
use crate::rtsp::tcp::{TcpBinding, TcpSecurityPolicy};
use fss_core::{CanonicalDecoder, CanonicalEncoder, DigestAlgorithm};
use fss_packet::{
    PacketLimits, ReorderLimits, StreamKey,
    jpeg::{JpegLimits, JpegReceiver},
};

const REQUEST: &str = "fss.rtsp_jpeg_import_request.v1";

impl JpegImportRequest {
    /// Canonical exact approval identity. No field is inferred from a camera URI or packet.
    pub fn digest(&self) -> Result<ContentDigest, JpegImportError> {
        Ok(ContentDigest::sha256(&self.encode()?))
    }

    fn validate(&self) -> Result<(), JpegImportError> {
        let scope = self.source.digest().map_err(source_error)?;
        let nonzero =
            |d: ContentDigest| d.algorithm() == DigestAlgorithm::Sha256 && d.bytes() != [0; 32];
        if self.pin.scope != scope
            || !nonzero(self.pin.head)
            || !nonzero(self.mapping_evidence)
            || !nonzero(self.replay.configuration_evidence)
            || self.pin.datagrams == 0
            || self.pin.datagrams > self.archive_limits.max_datagrams as u64
            || self.pin.payload_bytes == 0
            || self.pin.payload_bytes > self.archive_limits.max_payload_bytes
            || self.receive_time.0 < 0
            || self.replay.payload_type > 127
        {
            return Err(JpegImportError::Invalid(
                "source, mapping or capture boundary",
            ));
        }
        let limits = self.archive_limits;
        if !(1..=MAX_SOURCE_DATAGRAMS).contains(&limits.max_datagrams)
            || !(1..=MAX_SOURCE_BYTES).contains(&limits.max_payload_bytes)
            || !(1..=MAX_SCAN_ROOTS).contains(&limits.max_scan_roots)
            || !(1024..=32 * 1024 * 1024).contains(&limits.max_spool_object_bytes)
            || !(1..=MAX_FRAMES).contains(&self.max_frames)
            || !(1..=MAX_ORIGINAL_BYTES).contains(&self.max_original_bytes)
            || !(1..=MAX_MEDIA_BYTES).contains(&self.max_media_bytes)
            || !(1..=MAX_READ_BYTES).contains(&self.max_read_bytes)
            || !(1..=MAX_STEPS).contains(&self.max_steps)
        {
            return Err(JpegImportError::Limit("independent whole-call ceilings"));
        }
        // This constructs only bounded native receiver metadata; there is no source read,
        // payload admission or hidden interpretation fallback during approval validation.
        JpegReceiver::new(
            self.source.binding.key(),
            self.replay.payload_type,
            self.replay.reorder,
            self.replay.jpeg,
        )
        .map_err(source_error)?;
        Ok(())
    }

    pub(super) fn live_read_reservation(&self) -> u64 {
        self.archive_limits.max_payload_bytes
            + self.archive_limits.max_datagrams as u64 * (1024 + 512)
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>, JpegImportError> {
        self.validate()?;
        let mut e = CanonicalEncoder::new();
        e.text(REQUEST);
        let key = self.source.binding.key();
        e.u64((key.ingress >> 64) as u64);
        e.u64(key.ingress as u64);
        e.u64(key.generation);
        e.u32(key.ssrc);
        e.text(&self.source.binding.peer().to_string());
        e.text(self.source.binding.authority());
        match self.source.binding.security() {
            TcpSecurityPolicy::OwnerApprovedPlaintext => e.text("owner_approved_plaintext"),
        }
        e.tag(self.source.channels.0);
        e.tag(self.source.channels.1);
        e.digest(self.source.receive_clock);
        e.digest(self.source.retention_evidence);
        encode_pin(&mut e, self.pin);
        e.tag(self.replay.payload_type);
        e.bool(self.replay.reduced_rtcp);
        e.digest(self.replay.configuration_evidence);
        let ReorderLimits {
            packet,
            max_packets,
            max_bytes,
            max_delay_ns,
        } = self.replay.reorder;
        let PacketLimits {
            max_packet_bytes,
            max_extension_bytes,
            max_rtcp_packets,
        } = packet;
        for n in [
            max_packet_bytes,
            max_extension_bytes,
            max_rtcp_packets,
            max_packets,
            max_bytes,
        ] {
            e.u64(n as u64);
        }
        e.u64(max_delay_ns);
        let JpegLimits {
            max_frame_bytes,
            max_fragment_packets,
            max_pending_age_ns,
            max_cached_quantizers,
            max_dimension,
        } = self.replay.jpeg;
        for n in [max_frame_bytes, max_fragment_packets, max_cached_quantizers] {
            e.u64(n as u64);
        }
        e.u64(max_pending_age_ns);
        e.u32(u32::from(max_dimension));
        e.text(self.sensor.as_str());
        e.text(self.stream.as_str());
        e.digest(self.mapping_evidence);
        e.i128(self.receive_time.0);
        let DatagramArchiveLimits {
            max_datagrams,
            max_payload_bytes,
            max_scan_roots,
            max_spool_object_bytes,
        } = self.archive_limits;
        e.u64(max_datagrams as u64);
        e.u64(max_payload_bytes);
        e.u64(max_scan_roots as u64);
        e.u64(max_spool_object_bytes as u64);
        e.u64(self.max_frames as u64);
        e.u64(self.max_original_bytes);
        e.u64(self.max_media_bytes);
        e.u64(self.max_read_bytes);
        e.u64(self.max_steps);
        Ok(e.finish_checked()?)
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, FileIngestError> {
        if bytes.len() > 4096 {
            return Err(corrupt("request byte bound"));
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.text()? != REQUEST {
            return Err(corrupt("request domain"));
        }
        let key = StreamKey {
            ingress: (u128::from(d.u64()?) << 64) | u128::from(d.u64()?),
            generation: d.u64()?,
            ssrc: d.u32()?,
        };
        let peer = d.text()?.parse().map_err(|_| corrupt("source peer"))?;
        let authority = d.text()?;
        if d.text()? != "owner_approved_plaintext" {
            return Err(corrupt("source security"));
        }
        let binding = TcpBinding::new(
            key,
            peer,
            authority,
            TcpSecurityPolicy::OwnerApprovedPlaintext,
        )
        .map_err(|_| corrupt("source route"))?;
        let source = DatagramScope {
            binding,
            channels: (d.tag()?, d.tag()?),
            receive_clock: read_digest(&mut d)?,
            retention_evidence: read_digest(&mut d)?,
        };
        let pin = read_pin(&mut d)?;
        let payload_type = d.tag()?;
        let reduced_rtcp = d.bool()?;
        let configuration_evidence = read_digest(&mut d)?;
        let packet = PacketLimits {
            max_packet_bytes: read_size(&mut d)?,
            max_extension_bytes: read_size(&mut d)?,
            max_rtcp_packets: read_size(&mut d)?,
        };
        let reorder = ReorderLimits {
            packet,
            max_packets: read_size(&mut d)?,
            max_bytes: read_size(&mut d)?,
            max_delay_ns: d.u64()?,
        };
        let max_frame_bytes = read_size(&mut d)?;
        let max_fragment_packets = read_size(&mut d)?;
        let max_cached_quantizers = read_size(&mut d)?;
        let jpeg = JpegLimits {
            max_frame_bytes,
            max_fragment_packets,
            max_cached_quantizers,
            max_pending_age_ns: d.u64()?,
            max_dimension: u16::try_from(d.u32()?).map_err(|_| corrupt("dimension"))?,
        };
        let result = Self {
            source,
            pin,
            replay: JpegReplaySpec {
                payload_type,
                reduced_rtcp,
                configuration_evidence,
                reorder,
                jpeg,
            },
            sensor: SensorId::parse(d.text()?)?,
            stream: StreamId::parse(d.text()?)?,
            mapping_evidence: read_digest(&mut d)?,
            receive_time: TimestampNs(d.i128()?),
            archive_limits: DatagramArchiveLimits {
                max_datagrams: read_size(&mut d)?,
                max_payload_bytes: d.u64()?,
                max_scan_roots: read_size(&mut d)?,
                max_spool_object_bytes: read_size(&mut d)?,
            },
            max_frames: read_size(&mut d)?,
            max_original_bytes: d.u64()?,
            max_media_bytes: d.u64()?,
            max_read_bytes: d.u64()?,
            max_steps: d.u64()?,
        };
        d.ensure_finished()?;
        if result
            .encode()
            .map_err(|_| corrupt("request constraints"))?
            != bytes
        {
            return Err(corrupt("noncanonical request"));
        }
        Ok(result)
    }
}

pub(super) fn encode_pin(e: &mut CanonicalEncoder, pin: DatagramPin) {
    e.digest(pin.scope);
    e.digest(pin.head);
    e.u64(pin.datagrams);
    e.u64(pin.payload_bytes);
}
pub(super) fn read_pin(d: &mut CanonicalDecoder<'_>) -> Result<DatagramPin, FileIngestError> {
    Ok(DatagramPin {
        scope: read_digest(d)?,
        head: read_digest(d)?,
        datagrams: d.u64()?,
        payload_bytes: d.u64()?,
    })
}
pub(super) fn read_digest(d: &mut CanonicalDecoder<'_>) -> Result<ContentDigest, FileIngestError> {
    let value = d.digest()?;
    if value.algorithm() != DigestAlgorithm::Sha256 || value.bytes() == [0; 32] {
        return Err(corrupt("nonzero SHA-256 required"));
    }
    Ok(value)
}
pub(super) fn read_size(d: &mut CanonicalDecoder<'_>) -> Result<usize, FileIngestError> {
    usize::try_from(d.u64()?).map_err(|_| corrupt("size overflow"))
}
