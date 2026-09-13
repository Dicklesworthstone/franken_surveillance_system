#![forbid(unsafe_code)]
//! Fixture generation only.
//!
//! Deterministic virtual media fixture generators for FSS qualification.
//! Production runtime paths must never call these fixture generators.

pub mod jpeg;

pub use jpeg::{
    CustomMarker, GeneratedJpegFixture, GeneratedMjpegFixture, GeneratedMjpegFrame, JpegConfig,
    JpegError, Subsampling, build_jpeg_manifest_json, build_mjpeg_manifest_json, compute_psnr,
    compute_sha256_hex, encode_jpeg, encode_mjpeg, generate_all_jpeg_fixtures,
    generate_all_mjpeg_fixtures, simulate_float_idct_gray, source_pixels, write_all_media_fixtures,
};
