#![forbid(unsafe_code)]
//! Deterministic running-mean background subtraction on decoded luma planes.
//!
//! Maintains a per-pixel running mean and variance (Welford-style incremental
//! update). A pixel is foreground when its absolute deviation from the running
//! mean exceeds a scaled threshold. Connected foreground regions are extracted
//! via iterative flood fill and reported as bounding boxes with a foreground
//! density score. All arithmetic is integer or f64; no external crates.
//!
//! The background model adapts only on non-foreground pixels, so a genuinely
//! new object does not corrupt the model that detected it. The first frame is
//! always absorbed as the initial background with zero foreground output.

/// Configuration for the foreground detector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForegroundConfig {
    /// Minimum absolute luma deviation from the running mean for a pixel to be
    /// considered foreground, before the adaptive variance scale is applied.
    pub base_threshold: u16,
    /// Multiplier on the per-pixel standard deviation: a pixel is foreground
    /// when |pixel - mean| > base_threshold + threshold_sigma * stddev.
    /// Must be >= 1.
    pub threshold_sigma: u16,
    /// Background adaptation rate in 1/256 fixed point: 1 means instant
    /// adoption, 0 means never update. Values around 8..32 (1/32..1/8) are
    /// typical for indoor scenes.
    pub learning_rate_num: u16,
    /// Denominator for `learning_rate_num`; must be > learning_rate_num.
    pub learning_rate_den: u16,
    /// Minimum number of foreground pixels in a connected region for it to
    /// produce a bounding box.
    pub minimum_region_pixels: usize,
    /// Dimensions must match every observed frame; mismatched frames are
    /// refused.
    pub dimensions: [u32; 2],
}

impl ForegroundConfig {
    /// Validates hard bounds.
    pub fn validate(&self) -> Result<(), ForegroundError> {
        if self.dimensions[0] == 0 || self.dimensions[1] == 0 {
            return Err(ForegroundError::ZeroDimensions);
        }
        if self.base_threshold == 0 {
            return Err(ForegroundError::ZeroBaseThreshold);
        }
        if self.threshold_sigma == 0 {
            return Err(ForegroundError::ZeroBaseThreshold);
        }
        if self.learning_rate_den == 0 || self.learning_rate_num > self.learning_rate_den {
            return Err(ForegroundError::InvalidLearningRate);
        }
        if self.minimum_region_pixels == 0 {
            return Err(ForegroundError::ZeroMinimumRegion);
        }
        Ok(())
    }
}

/// Typed non-disclosing failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ForegroundError {
    /// Frame dimensions do not match the configured dimensions.
    DimensionMismatch {
        /// Configured width.
        expected_width: u32,
        /// Configured height.
        expected_height: u32,
        /// Actual frame width.
        actual_width: u32,
        /// Actual frame height.
        actual_height: u32,
    },
    /// Configured dimensions must be nonzero.
    ZeroDimensions,
    /// Base threshold must be nonzero.
    ZeroBaseThreshold,
    /// Threshold sigma must be nonzero.
    ZeroThresholdSigma,
    /// Learning rate must satisfy 0 < num <= den.
    InvalidLearningRate,
    /// Minimum region pixels must be nonzero.
    ZeroMinimumRegion,
    /// Frame pixel count does not match dimensions.
    PixelCountMismatch {
        /// Expected width * height.
        expected: usize,
        /// Actual pixel slice length.
        actual: usize,
    },
}
impl std::fmt::Display for ForegroundError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DimensionMismatch { expected_width, expected_height, actual_width, actual_height } => {
                write!(f, "dimension mismatch: expected {expected_width}x{expected_height}, got {actual_width}x{actual_height}")
            }
            Self::ZeroDimensions => write!(f, "dimensions must be nonzero"),
            Self::ZeroBaseThreshold | Self::ZeroThresholdSigma => write!(f, "threshold must be nonzero"),
            Self::InvalidLearningRate => write!(f, "learning rate must satisfy 0 < num <= den"),
            Self::ZeroMinimumRegion => write!(f, "minimum region pixels must be nonzero"),
            Self::PixelCountMismatch { expected, actual } => {
                write!(f, "pixel count mismatch: expected {expected}, got {actual}")
            }
        }
    }
}
impl std::error::Error for ForegroundError {}

/// Per-pixel running background model (mean and variance in f64).
struct BackgroundModel {
    mean: Vec<f64>,
    variance: Vec<f64>,
    /// Number of frames absorbed. The first frame sets the initial mean with
    /// zero variance; subsequent frames use an incremental update.
    frame_count: u64,
}

/// A bounding box around a connected foreground region.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForegroundBox {
    /// Left edge (column index, 0-based).
    pub x: u32,
    /// Top edge (row index, 0-based).
    pub y: u32,
    /// Box width in pixels (>= 1).
    pub width: u32,
    /// Box height in pixels (>= 1).
    pub height: u32,
    /// Foreground pixel count inside the box.
    pub pixel_count: usize,
    /// Fraction of box pixels that are foreground, in 1/256 fixed point (0..=256).
    pub density: u16,
}

/// Result of one frame processed by the foreground detector.
#[derive(Clone, Debug)]
pub struct ForegroundFrame {
    /// Binary foreground mask (row-major, same dimensions as the input).
    pub mask: Vec<bool>,
    /// Bounding boxes of connected foreground regions above the minimum area.
    pub boxes: Vec<ForegroundBox>,
    /// Total foreground pixel count across the mask.
    pub foreground_pixels: usize,
    /// True if the background model was initialized by this frame (first frame).
    pub baseline_initialized: bool,
}

/// Deterministic scene-model foreground detector on 8-bit grayscale frames.
pub struct ForegroundDetector {
    config: ForegroundConfig,
    model: Option<BackgroundModel>,
}

impl ForegroundDetector {
    /// Creates a new detector with the given configuration.
    pub fn new(config: ForegroundConfig) -> Result<Self, ForegroundError> {
        config.validate()?;
        Ok(Self { config, model: None })
    }

    /// Returns the configuration.
    #[must_use]
    pub fn config(&self) -> &ForegroundConfig { &self.config }

    /// Processes one 8-bit grayscale frame and returns the foreground result.
    ///
    /// On the first call the frame is absorbed as the initial background and
    /// the returned [`ForegroundFrame`] has an all-false mask and no boxes.
    /// On subsequent calls the frame is compared against the running model;
    /// deviating pixels are marked foreground and the model adapts only on
    /// background pixels.
    pub fn observe(
        &mut self,
        pixels: &[u8],
        width: u32,
        height: u32,
    ) -> Result<ForegroundFrame, ForegroundError> {
        let expected = self.config.dimensions;
        if width != expected[0] || height != expected[1] {
            return Err(ForegroundError::DimensionMismatch {
                expected_width: expected[0],
                expected_height: expected[1],
                actual_width: width,
                actual_height: height,
            });
        }
        let expected_pixels = width as usize * height as usize;
        if pixels.len() != expected_pixels {
            return Err(ForegroundError::PixelCountMismatch {
                expected: expected_pixels,
                actual: pixels.len(),
            });
        }

        let model = match &mut self.model {
            None => {
                // First frame: absorb as baseline, zero foreground.
                let mean: Vec<f64> = pixels.iter().map(|&p| f64::from(p)).collect();
                let variance = vec![0.0; expected_pixels];
                self.model = Some(BackgroundModel { mean, variance, frame_count: 1 });
                return Ok(ForegroundFrame {
                    mask: vec![false; expected_pixels],
                    boxes: Vec::new(),
                    foreground_pixels: 0,
                    baseline_initialized: true,
                });
            }
            Some(m) => m,
        };

        // 1. Compute foreground mask.
        let sigma_floor = f64::from(self.config.base_threshold);
        let sigma_scale = f64::from(self.config.threshold_sigma);
        let mut mask = vec![false; expected_pixels];
        let mut foreground_pixels = 0usize;
        for i in 0..expected_pixels {
            let deviation = (f64::from(pixels[i]) - model.mean[i]).abs();
            let stddev = model.variance[i].sqrt();
            let threshold = sigma_floor + sigma_scale * stddev;
            if deviation > threshold {
                mask[i] = true;
                foreground_pixels += 1;
            }
        }

        // 2. Adapt background on non-foreground pixels only.
        let lr_n = f64::from(self.config.learning_rate_num);
        let lr_d = f64::from(self.config.learning_rate_den);
        let alpha = lr_n / lr_d;
        for i in 0..expected_pixels {
            if !mask[i] {
                let delta = f64::from(pixels[i]) - model.mean[i];
                model.mean[i] += alpha * delta;
                model.variance[i] += alpha * (delta * delta - model.variance[i]);
            }
        }
        model.frame_count += 1;

        // 3. Connected component labeling (iterative flood fill) and bounding
        //    box extraction.
        let boxes = Self::extract_boxes(&mask, width, height, self.config.minimum_region_pixels);

        Ok(ForegroundFrame { mask, boxes, foreground_pixels, baseline_initialized: false })
    }

    /// Extracts bounding boxes from 4-connected foreground regions using an
    /// iterative flood fill. Regions below `minimum_region_pixels` are skipped.
    fn extract_boxes(
        mask: &[bool],
        width: u32,
        height: u32,
        minimum_pixels: usize,
    ) -> Vec<ForegroundBox> {
        let w = width as usize;
        let h = height as usize;
        let mut visited = vec![false; mask.len()];
        let mut boxes = Vec::new();

        for start in 0..mask.len() {
            if !mask[start] || visited[start] {
                continue;
            }
            // Iterative flood fill (avoids recursion depth issues).
            let mut stack = vec![start];
            visited[start] = true;
            let mut min_x = start % w;
            let mut max_x = min_x;
            let mut min_y = start / w;
            let mut max_y = min_y;
            let mut count = 0usize;

            while let Some(pixel) = stack.pop() {
                count += 1;
                let px = pixel % w;
                let py = pixel / w;
                if px < min_x { min_x = px; }
                if px > max_x { max_x = px; }
                if py < min_y { min_y = py; }
                if py > max_y { max_y = py; }

                // 4-connected neighbours.
                if px > 0 && mask[pixel - 1] && !visited[pixel - 1] {
                    visited[pixel - 1] = true;
                    stack.push(pixel - 1);
                }
                if px + 1 < w && mask[pixel + 1] && !visited[pixel + 1] {
                    visited[pixel + 1] = true;
                    stack.push(pixel + 1);
                }
                if py > 0 && mask[pixel - w] && !visited[pixel - w] {
                    visited[pixel - w] = true;
                    stack.push(pixel - w);
                }
                if py + 1 < h && mask[pixel + w] && !visited[pixel + w] {
                    visited[pixel + w] = true;
                    stack.push(pixel + w);
                }
            }

            if count >= minimum_pixels {
                let box_w = (max_x - min_x + 1) as u32;
                let box_h = (max_y - min_y + 1) as u32;
                let area = box_w as usize * box_h as usize;
                let density = ((count * 256) / area).min(256) as u16;
                boxes.push(ForegroundBox {
                    x: min_x as u32,
                    y: min_y as u32,
                    width: box_w,
                    height: box_h,
                    pixel_count: count,
                    density,
                });
            }
        }
        boxes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(w: u32, h: u32) -> ForegroundConfig {
        ForegroundConfig {
            base_threshold: 30,
            threshold_sigma: 2,
            learning_rate_num: 16,
            learning_rate_den: 256,
            minimum_region_pixels: 4,
            dimensions: [w, h],
        }
    }

    #[test]
    fn first_frame_is_baseline_with_zero_foreground() -> Result<(), Box<dyn std::error::Error>> {
        let mut det = ForegroundDetector::new(config(4, 4))?;
        let frame = det.observe(&[128; 16], 4, 4)?;
        assert!(frame.baseline_initialized);
        assert_eq!(frame.foreground_pixels, 0);
        assert!(frame.boxes.is_empty());
        Ok(())
    }

    #[test]
    fn bright_object_on_dark_background_produces_bounding_box() -> Result<(), Box<dyn std::error::Error>> {
        let mut det = ForegroundDetector::new(config(8, 8))?;
        let background = [20u8; 64];
        det.observe(&background, 8, 8)?;

        // Place a bright 3x3 block centred at (3,3).
        let mut frame_pixels = background;
        for y in 2..5 {
            for x in 2..5 {
                frame_pixels[y * 8 + x] = 220;
            }
        }
        let frame = det.observe(&frame_pixels, 8, 8)?;
        assert!(frame.foreground_pixels >= 9);
        assert_eq!(frame.boxes.len(), 1);
        let b = &frame.boxes[0];
        assert_eq!((b.x, b.y), (2, 2));
        assert_eq!((b.width, b.height), (3, 3));
        Ok(())
    }

    #[test]
    fn dimension_mismatch_is_refused() -> Result<(), Box<dyn std::error::Error>> {
        let mut det = ForegroundDetector::new(config(4, 4))?;
        let result = det.observe(&[128; 16], 8, 2);
        assert!(matches!(result, Err(ForegroundError::DimensionMismatch { .. })));
        Ok(())
    }

    #[test]
    fn pixel_count_mismatch_is_refused() -> Result<(), Box<dyn std::error::Error>> {
        let mut det = ForegroundDetector::new(config(4, 4))?;
        let result = det.observe(&[128; 15], 4, 4);
        assert!(matches!(result, Err(ForegroundError::PixelCountMismatch { .. })));
        Ok(())
    }

    #[test]
    fn empty_scene_produces_zero_detections() -> Result<(), Box<dyn std::error::Error>> {
        let mut det = ForegroundDetector::new(config(8, 8))?;
        let background = [100u8; 64];
        det.observe(&background, 8, 8)?;
        // Same background again: no deviation → no foreground.
        let frame = det.observe(&background, 8, 8)?;
        assert_eq!(frame.foreground_pixels, 0);
        assert!(frame.boxes.is_empty());
        Ok(())
    }

    #[test]
    fn background_adapts_after_object_is_removed() -> Result<(), Box<dyn std::error::Error>> {
        let mut det = ForegroundDetector::new(config(8, 8))?;
        let background = [100u8; 64];
        det.observe(&background, 8, 8)?;

        // Bright object for many frames: the model adapts on non-foreground
        // pixels, but the object pixels remain foreground.
        let mut object_frame = background;
        for y in 2..5 { for x in 2..5 { object_frame[y * 8 + x] = 200; } }
        for _ in 0..20 { det.observe(&object_frame, 8, 8)?; }

        // Remove the object: the model has adapted enough that the restored
        // background produces a (weaker) foreground response that decays over
        // subsequent observations.
        for _ in 0..30 { det.observe(&background, 8, 8)?; }
        let frame = det.observe(&background, 8, 8)?;
        assert_eq!(frame.foreground_pixels, 0, "background should have re-adapted");
        Ok(())
    }

    #[test]
    fn minimum_region_filters_tiny_artifacts() -> Result<(), Box<dyn std::error::Error>> {
        let mut det = ForegroundDetector::new(config(8, 8))?;
        let _ = det.observe(&[50u8; 64], 8, 8)?;
        // Single bright pixel: below minimum_region_pixels (4).
        let mut frame_pixels = [50u8; 64];
        frame_pixels[27] = 250;
        let frame = det.observe(&frame_pixels, 8, 8)?;
        assert!(frame.boxes.is_empty(), "single-pixel region must be filtered");
        Ok(())
    }

    #[test]
    fn two_separate_regions_produce_two_boxes() -> Result<(), Box<dyn std::error::Error>> {
        let mut det = ForegroundDetector::new(config(16, 8))?;
        let _ = det.observe(&[50u8; 128], 16, 8)?;
        let mut frame_pixels = [50u8; 128];
        for y in 1..4 { for x in 1..4 { frame_pixels[y * 16 + x] = 200; } }
        for y in 1..4 { for x in 10..13 { frame_pixels[y * 16 + x] = 200; } }
        let frame = det.observe(&frame_pixels, 16, 8)?;
        assert_eq!(frame.boxes.len(), 2, "two separated regions must yield two boxes");
        Ok(())
    }

    #[test]
    fn invalid_configs_are_refused() {
        assert!(ForegroundDetector::new(config(0, 4)).is_err());
        assert!(ForegroundDetector::new(config(4, 0)).is_err());
        let mut bad = config(4, 4);
        bad.base_threshold = 0;
        assert!(ForegroundDetector::new(bad).is_err());
        let mut bad = config(4, 4);
        bad.learning_rate_num = 300;
        bad.learning_rate_den = 256;
        assert!(ForegroundDetector::new(bad).is_err());
    }

    #[test]
    fn deterministic_across_runs() -> Result<(), Box<dyn std::error::Error>> {
        let pixels: Vec<u8> = (0..64).map(|i| if i % 7 == 0 { 200 } else { 50 }).collect();
        let mut a = ForegroundDetector::new(config(8, 8))?;
        let mut b = ForegroundDetector::new(config(8, 8))?;
        let fa = a.observe(&pixels, 8, 8)?;
        let fb = b.observe(&pixels, 8, 8)?;
        assert_eq!(fa.foreground_pixels, fb.foreground_pixels);
        assert_eq!(fa.boxes, fb.boxes);
        Ok(())
    }
}
