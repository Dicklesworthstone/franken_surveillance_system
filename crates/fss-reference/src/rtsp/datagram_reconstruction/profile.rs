#![forbid(unsafe_code)]
//! Hand-audited interpretation identity; no Debug or native-layout serialization.
use super::*;
use fss_packet::avc::{AvcAssemblyLimits, AvcSyntaxLimits};
use fss_packet::{H264Limits, PacketLimits, ReorderLimits};

pub(super) fn digest(source: DatagramPin, spec: AvcReplaySpec<'_>) -> Result<ContentDigest> {
    let mut e = CanonicalEncoder::new();
    e.text("fss.rtsp_datagram_avc_interpretation.v1");
    e.text(
        "receive-time-arrivals;drain-between-observations;arrival-wins-future-tie;no-prefix-eof",
    );
    e.digest(source.scope);
    e.digest(source.head);
    e.u64(source.datagrams);
    e.u64(source.payload_bytes);
    e.digest(spec.configuration_evidence);
    e.tag(spec.payload_type);
    e.tag(match spec.mode {
        H264Mode::SingleNal => 0,
        H264Mode::NonInterleaved => 1,
    });
    e.bool(spec.reduced_rtcp);
    e.digest(ContentDigest::sha256(spec.sps));
    e.digest(ContentDigest::sha256(spec.pps));
    // Exhaustive destructuring intentionally makes newly added semantic limits require review.
    let AvcReceiveLimits {
        reorder,
        reconstruction,
        syntax,
        assembly,
    } = spec.limits;
    let ReorderLimits {
        packet,
        max_packets,
        max_bytes,
        max_delay_ns,
    } = reorder;
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
        e.u64(u64::try_from(n).map_err(|_| AvcReplayError::Configuration)?);
    }
    e.u64(max_delay_ns);
    let H264Limits {
        max_nal_bytes,
        max_packet_nals,
        max_fragment_packets,
        max_pending_age_ns,
    } = reconstruction;
    for n in [max_nal_bytes, max_packet_nals, max_fragment_packets] {
        e.u64(u64::try_from(n).map_err(|_| AvcReplayError::Configuration)?);
    }
    e.u64(max_pending_age_ns);
    let AvcSyntaxLimits {
        max_nal_bytes,
        max_parameter_set_bytes,
        max_width,
        max_height,
        max_luma_samples,
        max_reference_frames,
        max_slice_identity_bits,
    } = syntax;
    for n in [
        max_nal_bytes,
        max_parameter_set_bytes,
        max_slice_identity_bits,
    ] {
        e.u64(u64::try_from(n).map_err(|_| AvcReplayError::Configuration)?);
    }
    e.u32(max_width);
    e.u32(max_height);
    e.u64(max_luma_samples);
    e.u32(max_reference_frames);
    let AvcAssemblyLimits {
        max_nals,
        max_bytes,
        max_age_ns,
    } = assembly;
    e.u64(u64::try_from(max_nals).map_err(|_| AvcReplayError::Configuration)?);
    e.u64(u64::try_from(max_bytes).map_err(|_| AvcReplayError::Configuration)?);
    e.u64(max_age_ns);
    let bytes = e
        .finish_checked()
        .map_err(|_| AvcReplayError::Configuration)?;
    ContentDigest::try_sha256(&bytes).map_err(|_| AvcReplayError::Configuration)
}
