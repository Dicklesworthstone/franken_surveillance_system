#![forbid(unsafe_code)]
//! Canonical transport interpretation; all semantic ceilings are included explicitly.
use super::*;
use fss_packet::PacketLimits;

pub(super) fn digest(source: DatagramPin, spec: JpegReplaySpec) -> Result<ContentDigest> {
    let mut e = CanonicalEncoder::new();
    e.text("fss.rtsp_datagram_jpeg_interpretation.v1");
    e.text(
        "receive-time-arrivals;drain-between-observations;arrival-wins-future-tie;no-prefix-eof",
    );
    e.digest(source.scope);
    e.digest(source.head);
    e.u64(source.datagrams);
    e.u64(source.payload_bytes);
    e.digest(spec.configuration_evidence);
    e.tag(spec.payload_type);
    e.bool(spec.reduced_rtcp);
    // Exhaustive destructuring forces review when a native semantic bound is added.
    let ReorderLimits {
        packet,
        max_packets,
        max_bytes,
        max_delay_ns,
    } = spec.reorder;
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
        e.u64(u64::try_from(n).map_err(|_| JpegReplayError::Configuration)?);
    }
    e.u64(max_delay_ns);
    let JpegLimits {
        max_frame_bytes,
        max_fragment_packets,
        max_pending_age_ns,
        max_cached_quantizers,
        max_dimension,
    } = spec.jpeg;
    for n in [max_frame_bytes, max_fragment_packets, max_cached_quantizers] {
        e.u64(u64::try_from(n).map_err(|_| JpegReplayError::Configuration)?);
    }
    e.u64(max_pending_age_ns);
    e.u32(u32::from(max_dimension));
    e.text(fss_packet::jpeg::JPEG_RECONSTRUCTION_PROFILE);
    e.text("full-prefix-cached-quantizers;original-admission-source;capture-clock-unknown");
    let bytes = e
        .finish_checked()
        .map_err(|_| JpegReplayError::Configuration)?;
    ContentDigest::try_sha256(&bytes).map_err(|_| JpegReplayError::Configuration)
}
