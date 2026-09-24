#![forbid(unsafe_code)]
//! Bounded scene renderer and source-embedded canonical recipe.
use super::*;
use fss_core::{CanonicalEncode, CanonicalEncoder};

pub(super) fn rectangle(spec: &MjpegCameraSpec, index: u32) -> Option<SyntheticRectangle> {
    if index < spec.warmup_frames {
        return None;
    }
    let columns = u64::from(spec.width / 8 - 1);
    let rows = u64::from(spec.height / 8 - 1);
    let phase = (spec.seed % columns + u64::from(index - spec.warmup_frames)) % columns;
    Some(SyntheticRectangle {
        x: phase as u16 * 8,
        y: ((spec.seed >> 32) % rows) as u16 * 8,
        width: 16,
        height: 16,
    })
}

pub(super) fn render(
    spec: &MjpegCameraSpec,
    rectangle: Option<SyntheticRectangle>,
    budget: &mut MjpegSourceBudget<'_>,
) -> Result<Vec<u8>, MjpegSourceError> {
    budget.reserve(u64::from(spec.width) * u64::from(spec.height))?;
    let width = usize::from(spec.width);
    let mut pixels = vec![32_u8; width * usize::from(spec.height)];
    for (y, row) in pixels.chunks_exact_mut(width).enumerate() {
        budget.check()?;
        if let Some(rect) = rectangle
            && y >= usize::from(rect.y)
            && y < usize::from(rect.y + rect.height)
        {
            row[usize::from(rect.x)..usize::from(rect.x + rect.width)].fill(224);
        }
    }
    Ok(pixels)
}

pub(super) fn recipe(
    spec: &MjpegCameraSpec,
    index: u32,
    capture: CaptureInterval,
    rectangle: Option<SyntheticRectangle>,
) -> Vec<u8> {
    FrameRecipe {
        spec,
        index,
        capture,
        rectangle,
    }
    .canonical_bytes()
}
struct FrameRecipe<'a> {
    spec: &'a MjpegCameraSpec,
    index: u32,
    capture: CaptureInterval,
    rectangle: Option<SyntheticRectangle>,
}
impl CanonicalEncode for FrameRecipe<'_> {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text("fss.virtual_mjpeg.rectangle.v1");
        encoder.text("synthetic fixture; not observed person presence or calibration");
        self.spec.capture_id.encode_canonical(encoder);
        self.spec.sensor_id.encode_canonical(encoder);
        encoder.u64(self.spec.seed);
        encoder.u64(u64::from(self.spec.frame_count));
        encoder.u64(u64::from(self.spec.width));
        encoder.u64(u64::from(self.spec.height));
        CaptureInterval::point(TimestampNs(self.spec.start_ns)).encode_canonical(encoder);
        encoder.u64(self.spec.period_ns);
        encoder.u64(self.spec.uncertainty_ns);
        encoder.u64(self.spec.packet_bytes as u64);
        encoder.u64(u64::from(self.spec.warmup_frames));
        encoder.u64(u64::from(self.index));
        self.capture.encode_canonical(encoder);
        encoder.u64(32); // background luma
        encoder.u64(224); // foreground luma
        match self.rectangle {
            None => encoder.u64(0),
            Some(rect) => {
                encoder.u64(1);
                for value in [rect.x, rect.y, rect.width, rect.height] {
                    encoder.u64(u64::from(value));
                }
            }
        }
    }
}
