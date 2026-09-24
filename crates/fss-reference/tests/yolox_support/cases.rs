//! Deterministic YOLOX-Nano conformance inputs shared by the lab example and the Rust test.
//!
//! Three sources: a procedural color pattern, a repository JPEG fixture decoded by the native
//! color decoder, and a procedural person-shaped silhouette (`person.rs`, which every including
//! crate must also declare as module `person`). Every pixel is integer arithmetic;
//! the model-input tensor the lab oracle saw is pinned by its SHA-256 in the fixture.

use fss_codec_mjpeg::color::{RgbDecodeLimits, decode_rgb};
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget};
use fss_core::ContentDigest;

/// Case names in fixture order.
pub const CASES: [&str; 3] = ["synthetic_pattern", "jpeg_colorbars", "silhouette"];

const JPEG: &[u8] =
    include_bytes!("../../../../tests/fixtures/media/jpeg/rgb_64x48_colorbars_420.jpg");

/// A source image in tightly packed RGB order.
pub struct SourceImage {
    /// Width, height.
    pub dimensions: [u32; 2],
    /// `width * height * 3` bytes.
    pub pixels: Vec<u8>,
    /// Exact JPEG bytes when the image came from a native decode.
    pub jpeg: Option<&'static [u8]>,
}

fn pattern() -> SourceImage {
    let (w, h) = (416_u32, 416_u32);
    let mut pixels = Vec::with_capacity((w * h * 3) as usize);
    for y in 0..h {
        for x in 0..w {
            pixels.push(((x * 3 + y) % 256) as u8);
            pixels.push(((x ^ y) & 255) as u8);
            pixels.push(((x * y) % 251) as u8);
        }
    }
    SourceImage {
        dimensions: [w, h],
        pixels,
        jpeg: None,
    }
}

/// Person-shaped silhouette on a gradient with deterministic hash noise (portrait 360x640),
/// drawn by the shared generator (`person.rs`, which the including crate declares as `person`).
fn silhouette() -> SourceImage {
    SourceImage {
        dimensions: super::person::PERSON_SCENE_DIMENSIONS,
        pixels: super::person::person_scene(Some(180)),
        jpeg: None,
    }
}

fn jpeg() -> Result<SourceImage, Box<dyn std::error::Error>> {
    let image = decode_rgb(
        JPEG,
        ContentDigest::sha256(JPEG).bytes(),
        ComponentInterpretation::YCbCr,
        RgbDecodeLimits::default(),
        &mut DecodeBudget::new(100_000_000),
    )?;
    Ok(SourceImage {
        dimensions: image.dimensions(),
        pixels: image.pixels().to_vec(),
        jpeg: Some(JPEG),
    })
}

/// Build one named case.
pub fn source(name: &str) -> Result<SourceImage, Box<dyn std::error::Error>> {
    match name {
        "synthetic_pattern" => Ok(pattern()),
        "jpeg_colorbars" => jpeg(),
        "silhouette" => Ok(silhouette()),
        _ => Err(format!("unknown case {name}").into()),
    }
}
