#![forbid(unsafe_code)]
//! Retained H.264/H.265 4:2:0 pictures (luma plus Cb/Cr) to tightly packed RGB.
//!
//! The admitted H.264 and H.265 profiles are 8-bit 4:2:0 and the codecs do not expose the SPS
//! VUI colour description, so the matrix is a declared choice, not an inference: ITU-R BT.601,
//! limited ("video") range, which is also what an unspecified `matrix_coefficients` means for
//! standard-definition content and what FFmpeg's default `yuv420p -> rgb24` conversion applies.
//! Arithmetic follows the MJPEG colour path (`fss_codec_mjpeg::color`) exactly: fixed Q16
//! coefficients, half-up rounding, saturation to 0..=255, and nearest-cell chroma replication
//! (pixel `(x, y)` uses chroma sample `(x / 2, y / 2)`). Only the matrix differs: JPEG/JFIF is
//! full range, video is limited range. Content coded with another matrix or full range would
//! be converted with a declared-wrong matrix; the transform identity makes that choice
//! auditable. This is a coded-pixel transform, not colour management.

use fss_codec_mjpeg::ComponentInterpretation;
use fss_codec_mjpeg::color::RgbDecodeReceipt;
use fss_core::{CanonicalEncoder, ContentDigest};

use super::RecordedDecodeError;

/// Versioned label of the declared video colour transform.
pub const VIDEO_RGB_TRANSFORM: &str =
    "fss.video_rgb_transform.v1:bt601-limited-range:q16-half-up:nearest-chroma:rgb-hwc";
/// Canonical domain of the per-frame decoder identity recorded in an RGB decode receipt.
pub const VIDEO_RGB_RECEIPT_DOMAIN: &str = "fss.video_rgb_receipt.v1";
/// Colour label used in reports for frames converted by this transform.
pub const VIDEO_RGB_COLOR: &str = "ycbcr420_bt601_limited_rgb";

// Q16 BT.601 limited-range coefficients: round(c * 65536) of 255/219, 1.402*255/224,
// 0.344136*255/224, 0.714136*255/224 and 1.772*255/224.
const Y_SCALE: i32 = 76_309;
const CR_TO_R: i32 = 104_597;
const CB_TO_G: i32 = 25_675;
const CR_TO_G: i32 = 53_279;
const CB_TO_B: i32 = 132_201;

/// Identity of [`VIDEO_RGB_TRANSFORM`]; a semantics label, not a hash of compiled code.
#[must_use]
pub fn video_rgb_transform_identity() -> ContentDigest {
    ContentDigest::sha256(VIDEO_RGB_TRANSFORM.as_bytes())
}

/// One BT.601 limited-range sample triple to RGB (Q16, half-up, saturating).
#[must_use]
pub fn ycbcr_limited_to_rgb(y: u8, cb: u8, cr: u8) -> [u8; 3] {
    let y = (i32::from(y) - 16) * Y_SCALE;
    let cb = i32::from(cb) - 128;
    let cr = i32::from(cr) - 128;
    let channel = |value: i32| ((value + 32_768).div_euclid(65_536)).clamp(0, 255) as u8;
    [
        channel(y + CR_TO_R * cr),
        channel(y - CB_TO_G * cb - CR_TO_G * cr),
        channel(y + CB_TO_B * cb),
    ]
}

/// Converts tight 4:2:0 planes (chroma `ceil(w/2) x ceil(h/2)`) to packed RGB.
pub fn i420_to_rgb(
    luma: &[u8],
    cb: &[u8],
    cr: &[u8],
    dimensions: [u32; 2],
) -> Result<Vec<u8>, RecordedDecodeError> {
    let [width, height] = dimensions.map(|v| v as usize);
    let chroma_width = width.div_ceil(2);
    let count = width
        .checked_mul(height)
        .filter(|n| *n > 0 && *n <= 4_194_304)
        .ok_or(RecordedDecodeError::Limit)?;
    let chroma = chroma_width * height.div_ceil(2);
    if luma.len() != count || cb.len() != chroma || cr.len() != chroma {
        return Err(RecordedDecodeError::InvalidReceipt);
    }
    let mut rgb = Vec::new();
    rgb.try_reserve_exact(count * 3)
        .map_err(|_| RecordedDecodeError::Limit)?;
    for y in 0..height {
        let row = &luma[y * width..(y + 1) * width];
        let chroma_row = (y / 2) * chroma_width;
        for (x, sample) in row.iter().enumerate() {
            let c = chroma_row + x / 2;
            rgb.extend_from_slice(&ycbcr_limited_to_rgb(*sample, cb[c], cr[c]));
        }
    }
    Ok(rgb)
}

/// Complete RGB decode receipt for a retained video picture converted by this transform.
///
/// `encoded_sha256` is the retained segment's source digest, `codec_receipt` the retained
/// frame receipt digest and `i420` its packed-plane digest; all three are bound into the
/// recorded decoder identity together with [`VIDEO_RGB_TRANSFORM`].
#[must_use]
pub fn video_rgb_receipt(
    encoded_sha256: [u8; 32],
    codec_receipt: ContentDigest,
    i420: ContentDigest,
    dimensions: [u32; 2],
    rgb: &[u8],
) -> RgbDecodeReceipt {
    let mut e = CanonicalEncoder::new();
    e.text(VIDEO_RGB_RECEIPT_DOMAIN);
    e.digest(video_rgb_transform_identity());
    e.digest(codec_receipt);
    e.digest(i420);
    RgbDecodeReceipt {
        encoded_sha256,
        rgb_sha256: ContentDigest::sha256(rgb).bytes(),
        decoder: ContentDigest::sha256(&e.finish()).bytes(),
        interpretation: ComponentInterpretation::YCbCr,
        dimensions,
        mcus: 0,
        entropy_blocks: 0,
        restarts: 0,
        metadata_segments: 0,
        metadata_bytes: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hand_computed_pixels_match_the_declared_q16_bt601_limited_matrix() {
        // Nominal white and black.
        assert_eq!(ycbcr_limited_to_rgb(235, 128, 128), [255, 255, 255]);
        assert_eq!(ycbcr_limited_to_rgb(16, 128, 128), [0, 0, 0]);
        // (81, 90, 240): Y' = 65 * 76309 = 4_960_085, cb = -38, cr = 112.
        // R = 4_960_085 + 104_597 * 112 = 16_674_949 -> (x + 32768) / 65536 = 254.93 -> 254.
        // G = 4_960_085 + 25_675 * 38 - 53_279 * 112 = -31_513 -> 0.
        // B = 4_960_085 - 132_201 * 38 = -63_553 -> saturates to 0.
        assert_eq!(ycbcr_limited_to_rgb(81, 90, 240), [254, 0, 0]);
        // (126, 100, 150): Y' = 110 * 76309 = 8_393_990, cb = -28, cr = 22.
        // R = 8_393_990 + 2_301_134 = 10_695_124 -> 163.69 -> 163.
        // G = 8_393_990 + 718_900 - 1_172_138 = 7_940_752 -> 121.67 -> 121.
        // B = 8_393_990 - 3_701_628 = 4_692_362 -> 72.10 -> 72.
        assert_eq!(ycbcr_limited_to_rgb(126, 100, 150), [163, 121, 72]);
    }

    #[test]
    fn chroma_is_replicated_nearest_cell_including_odd_edges() -> Result<(), RecordedDecodeError> {
        // 3x3 luma, 2x2 chroma: column 2 and row 2 use the last chroma cell.
        let luma = [16_u8, 235, 16, 235, 16, 235, 16, 235, 126];
        let cb = [128_u8, 128, 128, 100];
        let cr = [128_u8, 128, 128, 150];
        let rgb = i420_to_rgb(&luma, &cb, &cr, [3, 3])?;
        assert_eq!(rgb.len(), 27);
        assert_eq!(&rgb[0..3], &[0, 0, 0]);
        assert_eq!(&rgb[3..6], &[255, 255, 255]);
        assert_eq!(&rgb[24..27], &[163, 121, 72]);
        assert!(matches!(
            i420_to_rgb(&luma, &cb[..3], &cr, [3, 3]),
            Err(RecordedDecodeError::InvalidReceipt)
        ));
        assert!(matches!(
            i420_to_rgb(&[], &[], &[], [0, 0]),
            Err(RecordedDecodeError::Limit)
        ));
        Ok(())
    }
}
