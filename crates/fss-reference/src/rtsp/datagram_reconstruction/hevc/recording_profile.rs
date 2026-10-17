#![forbid(unsafe_code)]
use super::*;
pub(super) fn digest(
    receiver: ContentDigest,
    spec: &HevcRecordingReplaySpec,
) -> std::result::Result<ContentDigest, HevcRecordingReplayError> {
    let mut e = CanonicalEncoder::new();
    e.text("fss.datagram_hevc_recording_interpretation.v1");
    e.text("drain-capture-and-nals;expire-group-before-next-event;explicit-prefix-seal;no-invented-eof");
    e.digest(receiver);
    e.digest(spec.timing_evidence);
    e.text(spec.scope.sensor.as_str());
    e.text(spec.scope.stream.as_str());
    e.u64(spec.scope.generation);
    e.digest(spec.scope.anchor);
    e.digest(spec.scope.receive_clock);
    e.u32(spec.time_scale);
    e.bytes(spec.configuration.vps());
    e.bytes(spec.configuration.sps());
    e.bytes(spec.configuration.pps());
    let HevcAssemblyLimits {
        max_nals,
        max_bytes,
        max_source_spans,
        max_age_ns,
    } = spec.assembly;
    for n in [max_nals, max_bytes, max_source_spans] {
        e.u64(u64::try_from(n).map_err(|_| HevcRecordingReplayError::Configuration)?);
    }
    e.u64(max_age_ns);
    let CollectorLimits {
        max_packets,
        max_source_bytes,
        max_samples,
        max_picture_bytes,
        max_nals,
        max_source_spans,
        max_age_ns,
    } = spec.limits;
    for n in [
        max_packets,
        max_source_bytes,
        max_samples,
        max_picture_bytes,
        max_nals,
        max_source_spans,
    ] {
        e.u64(u64::try_from(n).map_err(|_| HevcRecordingReplayError::Configuration)?);
    }
    e.u64(max_age_ns);
    let bytes = e
        .finish_checked()
        .map_err(|_| HevcRecordingReplayError::Configuration)?;
    ContentDigest::try_sha256(&bytes).map_err(|_| HevcRecordingReplayError::Configuration)
}
