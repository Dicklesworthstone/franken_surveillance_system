//! Deterministic YOLOX-Nano conformance inputs shared by the lab example and the Rust test.
//!
//! Three sources: a procedural color pattern, a repository JPEG fixture decoded by the native
//! color decoder, and a procedural person-shaped silhouette. Every pixel is integer arithmetic;
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

/// Person-shaped silhouette on a gradient with deterministic hash noise (portrait 360x640).
fn silhouette() -> SourceImage {
    let (w, h) = (360_i64, 640_i64);
    let mut pixels = Vec::with_capacity((w * h * 3) as usize);
    for y in 0..h {
        for x in 0..w {
            let mut rgb: [i64; 3] = if y >= 560 {
                [90, 110, 70]
            } else {
                [
                    120 + (y * 60).div_euclid(h),
                    135 + (y * 40).div_euclid(h),
                    150 - (y * 50).div_euclid(h),
                ]
            };
            // Person drawn in local coordinates, one third scale about the foot point (180, 600).
            let u = (x - 180) * 3;
            let v = 600 - (600 - y) * 3;
            let cloth = [60, 70, 110];
            let skin = [205, 165, 135];
            let pants = [45, 45, 55];
            let mut put = |mask: bool, c: [i64; 3]| {
                if mask {
                    rgb = c;
                }
            };
            put(u * u + (v - 150) * (v - 150) <= 900, skin);
            put(
                u * u + (v - 140) * (v - 140) <= 1024 && v < 138,
                [50, 35, 25],
            );
            put(u.abs() <= 12 && (176..196).contains(&v), skin);
            if (192..380).contains(&v) {
                put(u.abs() <= 52 - ((v - 192) * 12).div_euclid(188), cloth);
            }
            if (198..370).contains(&v) {
                let off = 54 + ((v - 198) * 14).div_euclid(172);
                put(u >= -off - 22 && u < -off, cloth);
                put(u > off && u <= off + 22, cloth);
            }
            put((-84..-60).contains(&u) && (370..398).contains(&v), skin);
            put(u > 60 && u <= 84 && (370..398).contains(&v), skin);
            put((-42..-5).contains(&u) && (380..585).contains(&v), pants);
            put((5..42).contains(&u) && (380..585).contains(&v), pants);
            put(
                (-48..-2).contains(&u) && (585..600).contains(&v),
                [20, 20, 20],
            );
            put(
                (2..48).contains(&u) && (585..600).contains(&v),
                [20, 20, 20],
            );
            let noise = ((x * 73_856_093) ^ (y * 19_349_663)).rem_euclid(41) - 20;
            for c in rgb {
                pixels.push((c + noise).clamp(0, 255) as u8);
            }
        }
    }
    SourceImage {
        dimensions: [w as u32, h as u32],
        pixels,
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
