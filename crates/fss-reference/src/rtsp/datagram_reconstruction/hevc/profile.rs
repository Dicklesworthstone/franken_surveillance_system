#![forbid(unsafe_code)]
//! Canonical transport interpretation; all semantic ceilings are included explicitly.
use super::*;
use fss_packet::PacketLimits;

pub(super) fn digest(source: DatagramPin, spec: HevcReplaySpec) -> Result<ContentDigest> {
    let mut e = CanonicalEncoder::new();
    e.text("fss.rtsp_datagram_hevc_interpretation.v1");
    e.text(
        "receive-time-arrivals;drain-between-observations;arrival-wins-future-tie;no-prefix-eof",
    );
    e.digest(source.scope);
    e.digest(source.head);
    e.u64(source.datagrams);
    e.u64(source.payload_bytes);
    e.digest(spec.configuration_evidence);
    e.tag(spec.payload_type);
    e.u32(u32::from(spec.sprop_max_don_diff));
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
        e.u64(u64::try_from(n).map_err(|_| HevcReplayError::Configuration)?);
    }
    e.u64(max_delay_ns);
    let H265Limits {
        max_nal_bytes,
        max_packet_nals,
        max_fragment_packets,
        max_pending_age_ns,
    } = spec.reconstruction;
    for n in [max_nal_bytes, max_packet_nals, max_fragment_packets] {
        e.u64(u64::try_from(n).map_err(|_| HevcReplayError::Configuration)?);
    }
    e.u64(max_pending_age_ns);
    let bytes = e
        .finish_checked()
        .map_err(|_| HevcReplayError::Configuration)?;
    ContentDigest::try_sha256(&bytes).map_err(|_| HevcReplayError::Configuration)
}
