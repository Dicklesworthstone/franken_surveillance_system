#![forbid(unsafe_code)]
//! Applies a [`MaskBinding`] to decoded planes before any consumer sees them.
//!
//! Every masked luma sample becomes [`MASK_FILL_LUMA`]. A 4:2:0 chroma sample covers a 2x2 luma
//! block; it becomes [`MASK_FILL_CHROMA`] when *any* luma sample of its block is masked (the
//! conservative direction: colour never leaks from a masked pixel into a neighbour). Every masked
//! RGB pixel becomes [`MASK_FILL_RGB`], also after a video YCbCr-to-RGB conversion, so every RGB
//! consumer sees one fill regardless of the colour transform. A binding without a policy changes
//! nothing and is reported as such by the caller. A frame whose dimensions differ from the
//! policy's declared stream resolution is refused, never passed through unmasked.

use fss_codec_mjpeg::color::RgbDecodeReceipt;
use fss_core::{ContentDigest, DigestAlgorithm};

use super::{
    MASK_FILL_CHROMA, MASK_FILL_LUMA, MASK_FILL_RGB, MaskBinding, PrivacyMaskError,
    PrivacyMaskPolicy, lineage_digest,
};

/// How much of a zone a policy masks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZoneMasking {
    /// No masked pixel lies inside the zone.
    Unmasked,
    /// Some but not all pixels of the zone are masked.
    Partial,
    /// Every pixel of the zone is masked.
    Full,
}

impl ZoneMasking {
    /// Whether any pixel of the zone is masked.
    #[must_use]
    pub const fn any(self) -> bool {
        !matches!(self, Self::Unmasked)
    }
}

impl PrivacyMaskPolicy {
    /// Whether pixel `(x, y)` lies in a masked rectangle.
    #[must_use]
    pub fn masks(&self, x: u32, y: u32) -> bool {
        self.regions().iter().any(|r| {
            x >= r.x()
                && y >= r.y()
                && u64::from(x) < u64::from(r.x()) + u64::from(r.width())
                && u64::from(y) < u64::from(r.y()) + u64::from(r.height())
        })
    }

    /// Masked share of the image-space rectangle `[x, y, width, height]` (clipped to the
    /// declared resolution; an empty or fully outside rectangle is unmasked).
    #[must_use]
    pub fn zone_masking(&self, zone: [u32; 4]) -> ZoneMasking {
        let [width, height] = self.resolution();
        let [x, y, w, h] = zone;
        let right = (u64::from(x) + u64::from(w)).min(u64::from(width));
        let bottom = (u64::from(y) + u64::from(h)).min(u64::from(height));
        let (left, top) = (u64::from(x), u64::from(y));
        if left >= right || top >= bottom {
            return ZoneMasking::Unmasked;
        }
        // Coordinate compression: the clipped rectangle edges split the zone into at most
        // 65 x 65 cells, each wholly inside or wholly outside every rectangle.
        let clip = |value: u64, low: u64, high: u64| value.clamp(low, high);
        let mut xs = vec![left, right];
        let mut ys = vec![top, bottom];
        for r in self.regions() {
            xs.push(clip(u64::from(r.x()), left, right));
            xs.push(clip(u64::from(r.x()) + u64::from(r.width()), left, right));
            ys.push(clip(u64::from(r.y()), top, bottom));
            ys.push(clip(u64::from(r.y()) + u64::from(r.height()), top, bottom));
        }
        xs.sort_unstable();
        xs.dedup();
        ys.sort_unstable();
        ys.dedup();
        let total = (right - left) * (bottom - top);
        let mut masked = 0_u64;
        for rows in ys.windows(2) {
            for columns in xs.windows(2) {
                // Every coordinate is bounded by the declared resolution (<= 4096).
                if self.masks(columns[0] as u32, rows[0] as u32) {
                    masked += (columns[1] - columns[0]) * (rows[1] - rows[0]);
                }
            }
        }
        match masked {
            0 => ZoneMasking::Unmasked,
            m if m == total => ZoneMasking::Full,
            _ => ZoneMasking::Partial,
        }
    }
}

impl MaskBinding {
    fn active(&self, dimensions: [u32; 2]) -> Result<Option<&PrivacyMaskPolicy>, PrivacyMaskError> {
        let Some(policy) = self.policy() else {
            return Ok(None);
        };
        if policy.resolution() != dimensions {
            return Err(PrivacyMaskError::ResolutionMismatch {
                declared: policy.resolution(),
                decoded: dimensions,
            });
        }
        Ok(Some(policy))
    }

    fn pixel_count(dimensions: [u32; 2]) -> Result<usize, PrivacyMaskError> {
        let [w, h] = dimensions.map(|v| v as usize);
        w.checked_mul(h)
            .filter(|n| *n > 0 && *n <= 4_194_304)
            .ok_or(PrivacyMaskError::InvalidRecord)
    }

    /// Writes [`MASK_FILL_LUMA`] into every masked sample of a tight row-major luma plane.
    pub fn apply_luma(
        &self,
        luma: &mut [u8],
        dimensions: [u32; 2],
    ) -> Result<(), PrivacyMaskError> {
        let count = Self::pixel_count(dimensions)?;
        if luma.len() != count {
            return Err(PrivacyMaskError::InvalidRecord);
        }
        let Some(policy) = self.active(dimensions)? else {
            return Ok(());
        };
        let width = dimensions[0] as usize;
        for region in policy.regions() {
            let (x, y) = (region.x() as usize, region.y() as usize);
            let (w, h) = (region.width() as usize, region.height() as usize);
            for row in y..y + h {
                luma[row * width + x..row * width + x + w].fill(MASK_FILL_LUMA);
            }
        }
        Ok(())
    }

    /// Writes [`MASK_FILL_CHROMA`] into every tight 4:2:0 chroma sample (`ceil(w/2) x ceil(h/2)`)
    /// whose 2x2 luma block contains a masked sample.
    pub fn apply_chroma420(
        &self,
        cb: &mut [u8],
        cr: &mut [u8],
        dimensions: [u32; 2],
    ) -> Result<(), PrivacyMaskError> {
        Self::pixel_count(dimensions)?;
        let chroma_width = dimensions[0].div_ceil(2) as usize;
        let chroma = chroma_width * dimensions[1].div_ceil(2) as usize;
        if cb.len() != chroma || cr.len() != chroma {
            return Err(PrivacyMaskError::InvalidRecord);
        }
        let Some(policy) = self.active(dimensions)? else {
            return Ok(());
        };
        for region in policy.regions() {
            let first_column = (region.x() / 2) as usize;
            let last_column = ((region.x() + region.width() - 1) / 2) as usize;
            let first_row = (region.y() / 2) as usize;
            let last_row = ((region.y() + region.height() - 1) / 2) as usize;
            for row in first_row..=last_row {
                let start = row * chroma_width;
                cb[start + first_column..=start + last_column].fill(MASK_FILL_CHROMA);
                cr[start + first_column..=start + last_column].fill(MASK_FILL_CHROMA);
            }
        }
        Ok(())
    }

    /// Writes [`MASK_FILL_RGB`] into every masked pixel of tightly packed RGB.
    pub fn apply_rgb(&self, rgb: &mut [u8], dimensions: [u32; 2]) -> Result<(), PrivacyMaskError> {
        let count = Self::pixel_count(dimensions)?;
        if rgb.len() != count * 3 {
            return Err(PrivacyMaskError::InvalidRecord);
        }
        let Some(policy) = self.active(dimensions)? else {
            return Ok(());
        };
        let width = dimensions[0] as usize;
        for region in policy.regions() {
            let (x, y) = (region.x() as usize, region.y() as usize);
            let (w, h) = (region.width() as usize, region.height() as usize);
            for row in y..y + h {
                let span = &mut rgb[(row * width + x) * 3..(row * width + x + w) * 3];
                for pixel in span.as_chunks_mut::<3>().0 {
                    *pixel = MASK_FILL_RGB;
                }
            }
        }
        Ok(())
    }

    /// Per-pixel permission bytes for RGB privacy projection: 1 visible, 0 masked.
    pub fn allowed(&self, dimensions: [u32; 2]) -> Result<Vec<u8>, PrivacyMaskError> {
        let count = Self::pixel_count(dimensions)?;
        let mut allowed = vec![1_u8; count];
        if let Some(policy) = self.active(dimensions)? {
            let width = dimensions[0] as usize;
            for region in policy.regions() {
                let (x, y) = (region.x() as usize, region.y() as usize);
                let (w, h) = (region.width() as usize, region.height() as usize);
                for row in y..y + h {
                    allowed[row * width + x..row * width + x + w].fill(0);
                }
            }
        }
        Ok(allowed)
    }

    /// Masks a native RGB decode and returns the masked pixels with a receipt whose pixel digest
    /// matches them and whose decoder identity folds the binding. `None` without a policy: the
    /// caller keeps the unmodified decode, which then carries the explicit no-policy marker.
    pub fn mask_rgb_decode(
        &self,
        pixels: &[u8],
        receipt: RgbDecodeReceipt,
    ) -> Result<Option<(Vec<u8>, RgbDecodeReceipt)>, PrivacyMaskError> {
        if self.policy().is_none() {
            return Ok(None);
        }
        let mut rgb = pixels.to_vec();
        self.apply_rgb(&mut rgb, receipt.dimensions)?;
        let decoder = lineage_digest(
            "rgb_decoder",
            ContentDigest::new(DigestAlgorithm::Sha256, receipt.decoder),
            self.digest(),
        );
        let receipt = RgbDecodeReceipt {
            rgb_sha256: ContentDigest::sha256(&rgb).bytes(),
            decoder: decoder.bytes(),
            ..receipt
        };
        Ok(Some((rgb, receipt)))
    }
}
