//! Bounded image resizing before scalar Model IR execution.
//!
//! This extends, rather than changes, the strict-size `PreprocessProgram` v1 path.
//! Inputs must already be admitted and privacy-projected by the caller. Digests below
//! identify a computation, not camera custody, continuity, or permission to observe.

use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest, DigestAlgorithm, Generation, Sha256Hasher};
use fss_tensor::{DType, MAX_STORAGE_BYTES, Shape, Tensor};

use crate::scalar_executor::{ChannelTransform, ExecBudget, ExecError, PreprocessProgram, ScalarExecCx};

/// Versioned domain for resize programs; deliberately distinct from strict-size v1.
pub const RESIZE_PROGRAM_DOMAIN: &str = "fss.reference.image_resize.v1";

/// Pixel sampling rule. Neither mode uses a platform image or math library.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResizeFilter {
    /// Sample `floor(destination * source_size / destination_size)` on each axis.
    Nearest,
    /// Half-pixel centers, edge clamping, ordered F64 interpolation, then F32 rounding.
    Bilinear,
}

/// Whether to stretch the image or preserve its aspect ratio with explicit padding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResizeAspect {
    /// Fill the target independently along both axes.
    Stretch,
    /// Fit inside the target, floor the fitted size, and center with the extra pixel last.
    /// Padding is a raw U8 intensity applied to every input channel before conversion.
    Letterbox(u8),
}

/// Explicit sampling and resource policy for a single invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResizeOptions {
    /// Resampling filter.
    pub filter: ResizeFilter,
    /// Aspect-ratio and padding rule.
    pub aspect: ResizeAspect,
    /// Logical work units and logical pixel-buffer bytes admitted for this invocation.
    pub budget: ExecBudget,
}

/// Borrowed HWC U8 image, with a generation supplied by the owning decoder.
#[derive(Clone, Copy, Debug)]
pub struct ImageBytes<'a> {
    /// Complete, already-governed pixel bytes, without row padding.
    pub bytes: &'a [u8],
    /// Source height, strictly positive.
    pub height: usize,
    /// Source width, strictly positive.
    pub width: usize,
    /// One luminance channel or three RGB channels.
    pub channels: usize,
    /// Input generation; the returned tensor preserves it.
    pub generation: Generation,
}

/// Exact integer geometry of a resize, including the non-padding image rectangle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResizeGeometry {
    /// Original height.
    pub source_height: usize,
    /// Original width.
    pub source_width: usize,
    /// Model-input height.
    pub target_height: usize,
    /// Model-input width.
    pub target_width: usize,
    /// Height of the resized image excluding padding.
    pub image_height: usize,
    /// Width of the resized image excluding padding.
    pub image_width: usize,
    /// Top padding in model-input pixels.
    pub top: usize,
    /// Left padding in model-input pixels.
    pub left: usize,
}

impl ResizeGeometry {
    /// Maps an XYXY box in model-input pixel-edge coordinates to source pixels.
    /// Padding-only, nonfinite, reversed, and zero-area boxes return `None`.
    /// This maps geometry only; it does not assert a detection or visibility.
    #[must_use]
    pub fn source_box(&self, xyxy: [f64; 4]) -> Option<[f64; 4]> {
        if self.image_height == 0 || self.image_width == 0
            || self.source_height == 0 || self.source_width == 0
            || !xyxy.iter().all(|v| v.is_finite())
            || xyxy[0] >= xyxy[2] || xyxy[1] >= xyxy[3]
        {
            return None;
        }
        let x = |v: f64| (v - self.left as f64).clamp(0.0, self.image_width as f64)
            * self.source_width as f64 / self.image_width as f64;
        let y = |v: f64| (v - self.top as f64).clamp(0.0, self.image_height as f64)
            * self.source_height as f64 / self.image_height as f64;
        let result = [x(xyxy[0]), y(xyxy[1]), x(xyxy[2]), y(xyxy[3])];
        (result[0] < result[2] && result[1] < result[3]).then_some(result)
    }
}

/// Completed preprocessing with replay identities and no partially published tensor.
#[derive(Clone, Debug)]
pub struct ResizeOutcome {
    /// NCHW F32 tensor suitable for the existing scalar executor.
    pub tensor: Tensor,
    /// Geometry needed to reverse letterboxing in detection postprocessing.
    pub geometry: ResizeGeometry,
    /// Versioned transform identity; budgets do not change numerical semantics.
    pub program_digest: ContentDigest,
    /// HWC U8 content identity, including dimensions and generation.
    pub input_digest: ContentDigest,
    /// NCHW F32 content identity, including dimensions and generation.
    pub output_digest: ContentDigest,
    /// Charged logical work units, not elapsed time or calibrated hardware MACs.
    pub work_units: u64,
    /// Pixel-buffer bound, including input, intermediate F32 values, and output storage.
    pub buffer_bytes: usize,
}

struct ResizePlan {
    geometry: ResizeGeometry,
    shape: Shape,
    count: usize,
    input_bytes: usize,
    work: u64,
    bytes: usize,
}

fn invalid(reason: impl Into<String>) -> ExecError {
    ExecError::ShapeMismatch {
        node_id: "preprocess".to_owned(),
        op_id: RESIZE_PROGRAM_DOMAIN,
        reason: reason.into(),
    }
}

fn overflow(operation: &'static str) -> ExecError {
    ExecError::ArithmeticOverflow { operation }
}

fn admit(
    program: &PreprocessProgram,
    h: usize,
    w: usize,
    c: usize,
    options: ResizeOptions,
    tensor_copy: bool,
) -> Result<ResizePlan, ExecError> {
    let th = program.target_height;
    let tw = program.target_width;
    if h == 0 || w == 0 || th == 0 || tw == 0 {
        return Err(invalid("source and target dimensions must be positive"));
    }
    let out_c = match (program.channel_transform, c) {
        (ChannelTransform::Rgb, 3) => 3,
        (ChannelTransform::LumaOnly, 1 | 3) => 1,
        _ => return Err(invalid("expected RGB input or explicitly selected luminance input")),
    };
    let input_bytes = h.checked_mul(w).and_then(|v| v.checked_mul(c))
        .ok_or_else(|| overflow("resize input bytes"))?;
    if input_bytes > MAX_STORAGE_BYTES {
        return Err(invalid("resize input exceeds the tensor storage ceiling"));
    }
    let shape = Shape::new(vec![1, out_c, th, tw])?;
    let count = shape.num_elements()?;
    let output_bytes = shape.size_bytes(DType::F32)?;
    if output_bytes > MAX_STORAGE_BYTES {
        return Err(invalid("resize output exceeds the tensor storage ceiling"));
    }
    let bytes = input_bytes.checked_mul(if tensor_copy { 2 } else { 1 })
        .and_then(|v| output_bytes.checked_mul(2).and_then(|out| v.checked_add(out)))
        .ok_or_else(|| overflow("resize pixel-buffer bound"))?;
    let work = (count as u64).checked_mul(match options.filter {
        ResizeFilter::Nearest => 32,
        ResizeFilter::Bilinear => 96,
    }).and_then(|v| v.checked_add(input_bytes as u64))
        .and_then(|v| v.checked_add(output_bytes as u64))
        .ok_or_else(|| overflow("resize work bound"))?;
    if work > options.budget.max_macs || bytes > options.budget.max_bytes {
        return Err(ExecError::BudgetExceeded {
            macs: work, max_macs: options.budget.max_macs,
            bytes, max_bytes: options.budget.max_bytes,
        });
    }
    let (ih, iw) = match options.aspect {
        ResizeAspect::Stretch => (th, tw),
        ResizeAspect::Letterbox(_) => {
            // Products of two usize values fit u128 on supported 32/64-bit hosts.
            if (tw as u128) * (h as u128) <= (th as u128) * (w as u128) {
                ((((h as u128) * (tw as u128) / w as u128) as usize).max(1), tw)
            } else {
                (th, (((w as u128) * (th as u128) / h as u128) as usize).max(1))
            }
        }
    };
    Ok(ResizePlan {
        geometry: ResizeGeometry {
            source_height: h, source_width: w, target_height: th, target_width: tw,
            image_height: ih, image_width: iw, top: (th - ih) / 2, left: (tw - iw) / 2,
        },
        shape, count, input_bytes, work, bytes,
    })
}

impl PreprocessProgram {
    /// Computes the versioned resize identity, distinct from `canonical_bytes()` v1.
    #[must_use]
    pub fn resize_digest(&self, filter: ResizeFilter, aspect: ResizeAspect) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(RESIZE_PROGRAM_DOMAIN);
        encoder.bytes(&self.canonical_bytes());
        encoder.u8(match filter { ResizeFilter::Nearest => 1, ResizeFilter::Bilinear => 2 });
        match aspect {
            ResizeAspect::Stretch => encoder.u8(1),
            ResizeAspect::Letterbox(value) => { encoder.u8(2); encoder.u8(value); }
        }
        ContentDigest::sha256(&encoder.finish())
    }

    /// Resizes governed HWC bytes to NCHW F32 after validating dimensions and budgets.
    /// All allocation-sized arithmetic is checked before allocating. Cancellation is
    /// checked during hashing/sampling and again before returning any output.
    pub fn execute_resized_bytes(
        &self,
        image: ImageBytes<'_>,
        options: ResizeOptions,
        cx: &ScalarExecCx,
    ) -> Result<ResizeOutcome, ExecError> {
        cx.checkpoint("resize:admit")?;
        let plan = admit(self, image.height, image.width, image.channels, options, false)?;
        execute(self, image, options, cx, plan)
    }

    /// Resizes an HWC U8 tensor without permitting generation reassignment.
    /// The budget includes the temporary contiguous copy used by `Tensor::to_vec`.
    pub fn execute_resized(
        &self,
        input: &Tensor,
        options: ResizeOptions,
        cx: &ScalarExecCx,
    ) -> Result<ResizeOutcome, ExecError> {
        cx.checkpoint("resize:admit")?;
        if input.dtype() != DType::U8 {
            return Err(ExecError::UnsupportedDType {
                expected: DType::U8, actual: input.dtype(), tensor_name: "resize_input".to_owned(),
            });
        }
        let dims = input.shape().dims();
        if dims.len() != 3 { return Err(invalid("expected an HWC rank-three input tensor")); }
        let plan = admit(self, dims[0], dims[1], dims[2], options, true)?;
        let bytes = input.to_vec::<u8>()?;
        cx.checkpoint("resize:input-copy")?;
        execute(self, ImageBytes {
            bytes: &bytes, height: dims[0], width: dims[1], channels: dims[2],
            generation: input.generation(),
        }, options, cx, plan)
    }
}

fn pixel_header(dims: &[usize], generation: Generation, layout: &str) -> Vec<u8> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.reference.pixel_content.v1");
    encoder.text(layout);
    generation.encode_canonical(&mut encoder);
    encoder.u64(dims.len() as u64);
    for &dim in dims { encoder.u64(dim as u64); }
    encoder.finish()
}

fn finish_hash(hasher: Sha256Hasher) -> Result<ContentDigest, ExecError> {
    hasher.finalize().map(|bytes| ContentDigest::new(DigestAlgorithm::Sha256, bytes))
        .map_err(|_| overflow("resize content digest"))
}

fn execute(
    program: &PreprocessProgram,
    image: ImageBytes<'_>,
    options: ResizeOptions,
    cx: &ScalarExecCx,
    plan: ResizePlan,
) -> Result<ResizeOutcome, ExecError> {
    if image.bytes.len() != plan.input_bytes {
        return Err(invalid("input pixel length does not match HWC dimensions"));
    }
    let mut input_hash = Sha256Hasher::new();
    input_hash.update(&pixel_header(&[image.height, image.width, image.channels], image.generation, "hwc-u8"));
    for chunk in image.bytes.chunks(4096) {
        cx.checkpoint("resize:input-hash")?;
        input_hash.update(chunk);
    }
    let input_digest = finish_hash(input_hash)?;
    let mut values = Vec::new();
    values.try_reserve_exact(plan.count).map_err(|_| invalid("resize pixel allocation failed"))?;
    values.resize(plan.count, 0.0_f32);
    let g = plan.geometry;
    let plane = g.target_height * g.target_width;
    let scale = if program.scale_to_unit { 1.0_f32 / 255.0_f32 } else { 1.0_f32 };
    for y in 0..g.target_height {
        for x in 0..g.target_width {
            let flat = y * g.target_width + x;
            if flat % 1024 == 0 { cx.checkpoint("resize:sample")?; }
            let mut channels = [0.0_f32; 3];
            for (channel, value) in channels.iter_mut().take(image.channels).enumerate() {
                *value = if y < g.top || y - g.top >= g.image_height
                    || x < g.left || x - g.left >= g.image_width
                {
                    match options.aspect {
                        ResizeAspect::Letterbox(pad) => f32::from(pad),
                        ResizeAspect::Stretch => return Err(invalid("unexpected stretch padding")),
                    }
                } else {
                    sample(image, y - g.top, x - g.left, channel, g, options.filter)
                };
            }
            match program.channel_transform {
                ChannelTransform::Rgb => {
                    for channel in 0..3 { values[channel * plane + flat] = channels[channel] * scale; }
                }
                ChannelTransform::LumaOnly => {
                    // Keep the strict-size v1 operation order for bit-identical identity resize.
                    values[flat] = if image.channels == 1 { channels[0] * scale } else {
                        (0.299_f32 * channels[0] + 0.587_f32 * channels[1] + 0.114_f32 * channels[2]) * scale
                    };
                }
            }
        }
    }
    let mut output_hash = Sha256Hasher::new();
    output_hash.update(&pixel_header(plan.shape.dims(), image.generation, "nchw-f32-be"));
    for (index, value) in values.iter().enumerate() {
        if index % 1024 == 0 { cx.checkpoint("resize:output-hash")?; }
        output_hash.update(&value.to_bits().to_be_bytes());
    }
    let output_digest = finish_hash(output_hash)?;
    cx.checkpoint("resize:materialize")?;
    let tensor = Tensor::from_values(plan.shape, &values, image.generation)?;
    cx.checkpoint("resize:publish")?;
    Ok(ResizeOutcome {
        tensor, geometry: g, program_digest: program.resize_digest(options.filter, options.aspect),
        input_digest, output_digest, work_units: plan.work, buffer_bytes: plan.bytes,
    })
}

fn sample(image: ImageBytes<'_>, y: usize, x: usize, channel: usize, g: ResizeGeometry, filter: ResizeFilter) -> f32 {
    let at = |sy: usize, sx: usize| f64::from(image.bytes[(sy * image.width + sx) * image.channels + channel]);
    match filter {
        ResizeFilter::Nearest => {
            let sy = ((y as u128) * (image.height as u128) / g.image_height as u128) as usize;
            let sx = ((x as u128) * (image.width as u128) / g.image_width as u128) as usize;
            at(sy, sx) as f32
        }
        ResizeFilter::Bilinear => {
            let sy = ((y as f64 + 0.5) * image.height as f64 / g.image_height as f64 - 0.5)
                .clamp(0.0, (image.height - 1) as f64);
            let sx = ((x as f64 + 0.5) * image.width as f64 / g.image_width as f64 - 0.5)
                .clamp(0.0, (image.width - 1) as f64);
            let y0 = sy as usize;
            let x0 = sx as usize;
            let y1 = (y0 + 1).min(image.height - 1);
            let x1 = (x0 + 1).min(image.width - 1);
            let fy = sy - y0 as f64;
            let fx = sx - x0 as f64;
            let top = at(y0, x0) * (1.0 - fx) + at(y0, x1) * fx;
            let bottom = at(y1, x0) * (1.0 - fx) + at(y1, x1) * fx;
            (top * (1.0 - fy) + bottom * fy) as f32
        }
    }
}
