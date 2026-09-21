#![forbid(unsafe_code)]
//! Rational pixel-center bilinear interpolation with contributor-level permissions.
use super::{HogError, ForegroundSource, WorkBudget, ContentDigest, count, reserve, put};

pub(super) struct Resampled {
    pub source: ForegroundSource,
    pub pixels: Vec<u8>,
    pub allowed: Vec<u8>,
}
fn axis(position: u32, from: u32, to: u32) -> [(usize, u64); 2] {
    let denominator = i64::from(to) * 2;
    let numerator = (i64::from(position) * 2 + 1) * i64::from(from) - i64::from(to);
    let lower = numerator.div_euclid(denominator);
    let fraction = numerator.rem_euclid(denominator) as u64;
    [(lower.clamp(0, i64::from(from) - 1) as usize, denominator as u64 - fraction),
     ((lower + 1).clamp(0, i64::from(from) - 1) as usize, fraction)]
}
pub(super) fn resample(mut source: ForegroundSource, original: &[u8], permissions: &[u8],
    dimensions: [u32; 2], budget: &mut WorkBudget<'_>) -> Result<Resampled, HogError> {
    let n = count(dimensions)?;
    budget.charge(n as u64 * 2)?;
    let mut pixels = reserve(n)?; pixels.resize(n, 0_u8);
    let mut allowed = reserve(n)?; allowed.resize(n, 0_u8);
    let [width, height] = source.image.dimensions;
    let denominator = u64::from(dimensions[0]) * u64::from(dimensions[1]) * 4;
    for y in 0..dimensions[1] { for x in 0..dimensions[0] {
        budget.charge(32)?;
        let xs = axis(x, width, dimensions[0]); let ys = axis(y, height, dimensions[1]);
        // All actual contributors are checked BEFORE any intensity enters interpolation.
        let denied = ys.iter().any(|&(iy, wy)| xs.iter().any(|&(ix, wx)|
            wx != 0 && wy != 0 && permissions[iy * width as usize + ix] == 0));
        if denied { continue; }
        let mut total = 0_u64;
        for (iy, wy) in ys { for (ix, wx) in xs {
            if wx != 0 && wy != 0 { total += u64::from(original[iy * width as usize + ix]) * wx * wy; }
        }}
        let index = (y * dimensions[0] + x) as usize;
        pixels[index] = ((total + denominator / 2) / denominator) as u8;
        allowed[index] = 1;
    }}
    let mut identity = reserve(128)?;
    identity.extend_from_slice(b"fss/hog-scan/resize-centers-rational/1\0");
    identity.extend_from_slice(&source.image.image_domain);
    for value in source.image.dimensions.into_iter().chain(dimensions) { put(&mut identity, u64::from(value)); }
    budget.charge(n as u64 + identity.len() as u64)?;
    source.image.image_domain = ContentDigest::sha256(&identity).bytes();
    source.image.dimensions = dimensions;
    source.image.pixels = ContentDigest::sha256(&pixels).bytes();
    budget.charge(0)?;
    Ok(Resampled { source, pixels, allowed })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::localization::ImageIdentity;
    fn source(pixels: &[u8], dimensions: [u32; 2]) -> ForegroundSource {
        ForegroundSource { image: ImageIdentity { exposure: [1; 32], pixels: ContentDigest::sha256(pixels).bytes(),
            image_domain: [2; 32], dimensions }, camera: 1, calibration: [3; 32], clock: 1, capture: [4; 2] }
    }
    #[test]
    fn rational_centers_round_once_and_clamp_edges() -> Result<(), HogError> {
        let input = [0, 100, 200, 255]; let mut budget = WorkBudget::new(100_000);
        let result = resample(source(&input, [2, 2]), &input, &[1; 4], [1, 1], &mut budget)?;
        assert_eq!(result.pixels, [139]); assert_eq!(result.allowed, [1]);
        let result = resample(source(&input, [2, 2]), &input, &[1; 4], [4, 4], &mut budget)?;
        assert_eq!(result.pixels[0], 0); assert_eq!(result.pixels[15], 255);
        assert_eq!(result.pixels[5], 72); Ok(())
    }
    #[test]
    fn denied_contributors_do_not_leak_and_zero_weight_neighbors_do_not_deny() -> Result<(), HogError> {
        let input = [10, 200]; let mut budget = WorkBudget::new(100_000);
        let r = resample(source(&input, [2, 1]), &input, &[1, 0], [2, 1], &mut budget)?;
        assert_eq!(r.pixels, [10, 0]); assert_eq!(r.allowed, [1, 0]);
        let r = resample(source(&input, [2, 1]), &input, &[1, 0], [1, 1], &mut budget)?;
        assert_eq!(r.pixels, [0]); assert_eq!(r.allowed, [0]); Ok(())
    }
}
