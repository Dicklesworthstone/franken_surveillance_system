#![forbid(unsafe_code)]
//! Native parameter metadata from a complete first Matroska Tracks in the admitted prefix.

use crate::demux::{DemuxError, VideoCodec, probe_matroska_configuration};

use super::{
    ContainerKind, ParameterCodec, ParameterError, ParameterLimits, VideoParameters, checkpoint,
};

pub(super) fn probe<'a>(
    window: &'a [u8],
    incomplete: ParameterError,
    limits: ParameterLimits,
    cancelled: &mut impl FnMut() -> bool,
) -> Result<VideoParameters<'a>, ParameterError> {
    let mut check = || {
        if (cancelled)() {
            Err(DemuxError::Cancelled)
        } else {
            Ok(())
        }
    };
    let configuration =
        probe_matroska_configuration(window, &mut check).map_err(|error| match error {
            DemuxError::Truncated => incomplete,
            DemuxError::Limit => ParameterError::Limit,
            DemuxError::Cancelled => ParameterError::Cancelled,
            DemuxError::Unsupported | DemuxError::TrackSelection => ParameterError::Unsupported,
            DemuxError::DuplicateBox(_) => ParameterError::Contradictory,
            _ => ParameterError::Malformed,
        })?;
    let codec = match configuration.codec {
        VideoCodec::Avc => ParameterCodec::Avc,
        VideoCodec::Hevc => ParameterCodec::Hevc,
    };
    let (tuple, metadata, units) = super::configuration::parse_record(
        window,
        codec,
        configuration.private,
        limits,
        cancelled,
    )?;
    checkpoint(cancelled)?;
    let mut report = tuple.report(
        metadata,
        ContainerKind::Matroska,
        None,
        configuration.inspected_bytes,
        units,
    );
    report.track_number = Some(configuration.number);
    Ok(report)
}
