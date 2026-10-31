#![forbid(unsafe_code)]
//! Complete native JPEG decoding while keeping the exact RTP reconstruction and provenance.
//!
//! The supplied digest identifies the derived interchange JPEG, not original source datagrams.
//! Source custody remains independent; every refused decode returns the intact reconstruction.

use fss_codec_mjpeg::color::{DecodedRgb, RgbDecodeLimits};
use fss_codec_mjpeg::{
    ComponentInterpretation, DecodeBudget, DecodeError, DecodeLimits, DecodedLuma,
};
use fss_packet::jpeg::JpegFrame;

/// Fully validated pixels with the unforgeable reconstruction and source-byte maps.
#[derive(Debug)]
pub struct JpegPicture<P> {
    reconstruction: JpegFrame,
    pixels: P,
}
impl<P> JpegPicture<P> {
    /// Derived encoded image, packet dependencies and generated-header ranges.
    pub fn reconstruction(&self) -> &JpegFrame {
        &self.reconstruction
    }
    /// The actual decoder's validated immutable pixel image and lineage receipt.
    pub fn pixels(&self) -> &P {
        &self.pixels
    }
    /// Transfer both owners without discarding the source-to-derived mapping.
    pub fn into_parts(self) -> (JpegFrame, P) {
        (self.reconstruction, self.pixels)
    }
}

/// Complete full-range luma decoded from one admitted RFC 2435 frame.
pub type JpegLumaPicture = JpegPicture<DecodedLuma>;
/// Complete packed RGB decoded with the existing explicit JPEG YCbCr interpretation.
pub type JpegRgbPicture = JpegPicture<DecodedRgb>;

/// No partial pixels are exposed; the failed derivative stays available for source review.
#[derive(Debug)]
pub struct JpegPictureFailure {
    /// Existing typed native decode refusal; never raw compressed or decoded data.
    pub reason: DecodeError,
    /// Intact reconstruction, original packet references and generated ranges.
    pub reconstruction: Box<JpegFrame>,
}
impl std::fmt::Display for JpegPictureFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RTSP JPEG picture refusal: {:?}", self.reason)
    }
}
impl std::error::Error for JpegPictureFailure {}

/// Decode all luma and validate every chroma entropy block before returning pixels.
///
/// The owner supplies the independently computed digest of these derived JPEG bytes.
/// RFC 2435 types 0/1/64/65 specify three full-range Y/Cb/Cr components; interpretation
/// is therefore fixed here, not guessed from pixel appearance. Caller-narrowed limits
/// and the existing cancellable work budget reach the actual first-party decoder.
pub fn decode_luma_frame(
    reconstruction: JpegFrame,
    reconstruction_digest: [u8; 32],
    limits: DecodeLimits,
    budget: &mut DecodeBudget<'_>,
) -> Result<JpegLumaPicture, JpegPictureFailure> {
    let decoded = fss_codec_mjpeg::decode_luma(
        reconstruction.bytes(),
        reconstruction_digest,
        ComponentInterpretation::YCbCr,
        limits,
        budget,
    );
    finish(reconstruction, decoded)
}

/// Decode complete RGB through the existing pure-Rust JPEG color transform.
///
/// No capture time, orientation, ICC transform, calibration or original-file identity
/// is inferred. The encoded digest binds the exact derived image, and its reconstruction
/// carries the separately retainable original packet dependencies.
pub fn decode_rgb_frame(
    reconstruction: JpegFrame,
    reconstruction_digest: [u8; 32],
    limits: RgbDecodeLimits,
    budget: &mut DecodeBudget<'_>,
) -> Result<JpegRgbPicture, JpegPictureFailure> {
    let decoded = fss_codec_mjpeg::color::decode_rgb(
        reconstruction.bytes(),
        reconstruction_digest,
        ComponentInterpretation::YCbCr,
        limits,
        budget,
    );
    finish(reconstruction, decoded)
}

fn finish<P>(
    reconstruction: JpegFrame,
    decoded: Result<P, DecodeError>,
) -> Result<JpegPicture<P>, JpegPictureFailure> {
    match decoded {
        Ok(pixels) => Ok(JpegPicture {
            reconstruction,
            pixels,
        }),
        Err(reason) => Err(JpegPictureFailure {
            reason,
            reconstruction: Box::new(reconstruction),
        }),
    }
}
