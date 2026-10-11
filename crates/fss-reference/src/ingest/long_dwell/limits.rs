#![forbid(unsafe_code)]
//! Shared exact native read/codec/whole-scan reservations; no alternate decoder semantics.

use super::LongDwellLimits as LongWatchLimits;
use crate::ingest::RetainedReadLimits;
use crate::ingest::recorded_watch::{WatchError, WatchLimits};
use fss_core::{CanonicalDecoder, CanonicalEncoder};
type Result<T> = std::result::Result<T, WatchError>;

fn usize_value(decoder: &mut CanonicalDecoder<'_>) -> Result<usize> {
    usize::try_from(decoder.u64()?).map_err(|_| WatchError::Limit)
}
fn word_value(decoder: &mut CanonicalDecoder<'_>) -> Result<u32> {
    u32::try_from(decoder.u64()?).map_err(|_| WatchError::Limit)
}

/// Admit original exact reservations without narrowing or widening the retained recipe.
pub(in crate::ingest) fn validate_within(
    stored: &LongWatchLimits,
    allowed: &LongWatchLimits,
) -> Result<()> {
    stored.validate()?;
    allowed.validate()?;
    let mut s = CanonicalEncoder::new();
    let mut a = CanonicalEncoder::new();
    encode_limits(&mut s, stored);
    encode_limits(&mut a, allowed);
    let sb = s.finish();
    let ab = a.finish();
    let mut s = CanonicalDecoder::new(&sb);
    let mut a = CanonicalDecoder::new(&ab);
    while s.remaining() != 0 {
        if s.u64()? > a.u64()? {
            return Err(WatchError::Limit);
        }
    }
    a.ensure_finished()?;
    Ok(())
}

pub(in crate::ingest) fn encode_limits(encoder: &mut CanonicalEncoder, limits: &LongWatchLimits) {
    let decode = &limits.decode;
    for value in [
        decode.read_limits.max_source_bytes,
        decode.read_limits.max_chunk_bytes,
        decode.read_limits.max_segment_bytes,
        decode.jpeg_limits.maximum_bytes as u64,
        u64::from(decode.jpeg_limits.maximum_dimension),
        decode.jpeg_limits.maximum_pixels as u64,
        decode.jpeg_limits.maximum_markers as u64,
        decode.jpeg_work_units,
        u64::from(decode.h264_limits.max_width),
        u64::from(decode.h264_limits.max_height),
        u64::from(decode.h264_limits.max_macroblocks),
        decode.h264_limits.max_pictures,
        decode.h264_limits.max_nal_bytes as u64,
        u64::from(decode.h264_limits.max_slices_per_picture),
        u64::from(decode.h264_limits.max_reference_frames),
        u64::from(decode.h265_limits.max_width),
        u64::from(decode.h265_limits.max_height),
        decode.h265_limits.max_luma_samples,
        decode.h265_limits.max_pictures,
        decode.h265_limits.max_nal_bytes as u64,
        u64::from(decode.h265_limits.max_slices_per_picture),
        u64::from(decode.h265_limits.max_dpb_pictures),
        limits.maximum_source_chunk_bytes,
        limits.maximum_pixel_samples,
        limits.maximum_assignment_work,
        limits.maximum_trace_bytes as u64,
    ] {
        encoder.u64(value);
    }
}
pub(in crate::ingest) fn decode_limits(
    decoder: &mut CanonicalDecoder<'_>,
) -> Result<LongWatchLimits> {
    let read_limits = RetainedReadLimits {
        max_source_bytes: decoder.u64()?,
        max_chunk_bytes: decoder.u64()?,
        max_segment_bytes: decoder.u64()?,
    };
    let jpeg_limits = fss_codec_mjpeg::DecodeLimits {
        maximum_bytes: usize_value(decoder)?,
        maximum_dimension: word_value(decoder)?,
        maximum_pixels: usize_value(decoder)?,
        maximum_markers: usize_value(decoder)?,
    };
    let jpeg_work_units = decoder.u64()?;
    let h264_limits = fss_codec_h264::DecoderLimits {
        max_width: word_value(decoder)?,
        max_height: word_value(decoder)?,
        max_macroblocks: word_value(decoder)?,
        max_pictures: decoder.u64()?,
        max_nal_bytes: usize_value(decoder)?,
        max_slices_per_picture: word_value(decoder)?,
        max_reference_frames: word_value(decoder)?,
    };
    let h265_limits = fss_codec_h265::DecoderLimits {
        max_width: word_value(decoder)?,
        max_height: word_value(decoder)?,
        max_luma_samples: decoder.u64()?,
        max_pictures: decoder.u64()?,
        max_nal_bytes: usize_value(decoder)?,
        max_slices_per_picture: word_value(decoder)?,
        max_dpb_pictures: word_value(decoder)?,
    };
    Ok(LongWatchLimits {
        decode: WatchLimits {
            read_limits,
            jpeg_limits,
            jpeg_work_units,
            h264_limits,
            h265_limits,
        },
        maximum_source_chunk_bytes: decoder.u64()?,
        maximum_pixel_samples: decoder.u64()?,
        maximum_assignment_work: decoder.u64()?,
        maximum_trace_bytes: usize_value(decoder)?,
    })
}
