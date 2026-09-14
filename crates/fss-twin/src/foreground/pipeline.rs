#![forbid(unsafe_code)]
//! Native raw-luma -> rectification -> foreground -> masked-crop composition.
//! No image component is implicitly promoted to visible contact or a track identity.

use fss_core::ContentDigest;
use fss_geometry::{GeometryError, WorkBudget};
use crate::association::UnassignedContact;
use crate::rectification::{RawGrayFrame, RectificationError, RectificationPlan,
    RectificationReceipt, RectificationSpec, RectifiedFrame};
use super::{BackgroundModel, BackgroundPolicy, ForegroundError, ForegroundFrame,
    ForegroundPolicy, ForegroundReport, ForegroundSource, MAX_FOREGROUND_PIXELS,
    MAX_BACKGROUND_FRAMES, integer, reserve};

/// Capture timing and camera labels are owner-supplied, never read from wall time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameCapture {
    /// Physical camera handle matching the frozen background.
    pub camera: u64,
    /// Common capture-clock generation.
    pub clock: u64,
    /// Inclusive possible scene-capture interval.
    pub capture: [u64; 2],
}
/// A reference image and its unchanged external capture basis.
#[derive(Clone, Copy, Debug)]
pub struct RectifiedReference<'a> {
    /// Actual output of the native rectifier; not a user-forged image/receipt pair.
    pub frame: &'a RectifiedFrame,
    /// Owner-supplied timing/physical-camera binding.
    pub capture: FrameCapture,
}
/// Explicit failures; no partially rectified/classified/cropped output escapes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForegroundPipelineError {
    /// Source rectification failed before a usable report was produced.
    Rectification(RectificationError),
    /// Background, component, resource, source or timing failure.
    Foreground(ForegroundError),
    /// Wrong map, missing region, malformed crop or masked proposed contact.
    InvalidInput,
}
impl From<RectificationError> for ForegroundPipelineError {
    fn from(e: RectificationError) -> Self { Self::Rectification(e) }
}
impl From<ForegroundError> for ForegroundPipelineError {
    fn from(e: ForegroundError) -> Self { Self::Foreground(e) }
}
impl From<GeometryError> for ForegroundPipelineError {
    fn from(e: GeometryError) -> Self { Self::Foreground(e.into()) }
}
impl std::fmt::Display for ForegroundPipelineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Rectification(_) => "foreground source rectification failed",
            Self::Foreground(_) => "foreground candidate stage failed",
            Self::InvalidInput => "invalid foreground integration input",
        })
    }
}
impl std::error::Error for ForegroundPipelineError {}

/// Frozen reference model with the complete raw-to-derived lineage, not only hashes
/// of derivative images. Reference source receipts share their sources' privacy policy.
pub struct RectifiedBackground {
    model: BackgroundModel,
    spec: RectificationSpec,
    map: [u8; 32],
    output_domain: [u8; 32],
    receipts: Vec<RectificationReceipt>,
}
impl std::fmt::Debug for RectifiedBackground {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RectifiedBackground").field("references", &self.receipts.len()).finish_non_exhaustive()
    }
}
impl RectifiedBackground {
    /// Compile a selected reference set. Raw and derived masks, stride, range and
    /// exposure identity remain attached; the owner does not need a second detector.
    pub fn build(plan: &RectificationPlan, references: &[RectifiedReference<'_>],
        policy: BackgroundPolicy, budget: &mut WorkBudget<'_>) -> Result<Self, ForegroundPipelineError> {
        budget.charge(0)?;
        if !(3..=MAX_BACKGROUND_FRAMES).contains(&references.len()) { return Err(ForegroundError::Limit.into()); }
        let mut frames = reserve(references.len())?;
        let mut receipts = reserve(references.len())?;
        for reference in references {
            check_frame(plan, reference.frame)?;
            frames.push(borrow(reference.frame, reference.capture, budget)?);
            receipts.push(reference.frame.receipt());
        }
        let model = BackgroundModel::build(&frames, policy, budget)?;
        budget.charge(0)?;
        Ok(Self { model, spec: plan.spec(), map: plan.map_digest(),
            output_domain: plan.output_domain(), receipts })
    }
    /// Exact immutable numerical foreground model.
    pub fn model(&self) -> &BackgroundModel { &self.model }
    /// All original source-to-reference receipts in capture order.
    pub fn reference_receipts(&self) -> &[RectificationReceipt] { &self.receipts }
    /// Process actual decoded luma through the same map used by the references.
    /// No bounding box, target class, known contact or association is an input.
    pub fn detect_luma(&self, plan: &RectificationPlan, raw: &RawGrayFrame<'_>,
        capture: FrameCapture, policy: ForegroundPolicy, budget: &mut WorkBudget<'_>)
        -> Result<RectifiedForeground, ForegroundPipelineError> {
        budget.charge(0)?;
        if self.spec != plan.spec() || self.map != plan.map_digest() || self.output_domain != plan.output_domain() {
            return Err(ForegroundPipelineError::InvalidInput);
        }
        let frame = plan.apply(raw, budget)?;
        let report = self.model.detect(&borrow(&frame, capture, budget)?, policy, budget)?;
        budget.charge(0)?;
        Ok(RectifiedForeground { frame, report })
    }
}
fn check_frame(plan: &RectificationPlan, frame: &RectifiedFrame) -> Result<(), ForegroundPipelineError> {
    let receipt = frame.receipt();
    if frame.identity().image_domain != plan.output_domain() || receipt.map_digest != plan.map_digest()
        || frame.identity().dimensions != plan.spec().target.dimensions()
        || receipt.source.calibration != plan.spec().calibration
        || receipt.source.image_domain != plan.spec().source_domain
        || receipt.source.range != plan.spec().range {
        return Err(ForegroundPipelineError::InvalidInput);
    }
    Ok(())
}
fn borrow<'a>(frame: &'a RectifiedFrame, capture: FrameCapture, budget: &mut WorkBudget<'_>)
    -> Result<ForegroundFrame<'a>, ForegroundError> {
    ForegroundFrame::new(ForegroundSource { image: frame.identity(), camera: capture.camera,
        clock: capture.clock, capture: capture.capture, calibration: frame.receipt().source.calibration },
        frame.pixels(), frame.allowed(), budget)
}

/// Image proposals coupled to the actual rectification output and its raw-source receipt.
pub struct RectifiedForeground { frame: RectifiedFrame, report: ForegroundReport }
impl std::fmt::Debug for RectifiedForeground {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RectifiedForeground").field("report", &self.report).finish_non_exhaustive()
    }
}
impl RectifiedForeground {
    /// Computed regions, complete pixel labels and explicit unknown/omitted states.
    pub fn report(&self) -> &ForegroundReport { &self.report }
    /// Full pinhole image, its 0/1 permission mask and original source lineage.
    pub fn frame(&self) -> &RectifiedFrame { &self.frame }
    /// Extract a bounded context crop for a separately admitted semantic/contact model.
    /// Denied pixels remain zero with mask=0. Unknown BACKGROUND pixels may be
    /// included if currently permitted; model uncertainty is not a privacy mask.
    pub fn crop(&self, region: u32, padding: u32, maximum_pixels: usize,
        budget: &mut WorkBudget<'_>) -> Result<ForegroundCrop, ForegroundPipelineError> {
        budget.charge(0)?;
        if padding > 4096 || maximum_pixels == 0 || maximum_pixels > MAX_FOREGROUND_PIXELS {
            return Err(ForegroundPipelineError::InvalidInput);
        }
        budget.charge(self.report.regions().len() as u64)?;
        let component = self.report.regions().iter().find(|r| r.id == region)
            .ok_or(ForegroundPipelineError::InvalidInput)?;
        let dims = self.frame.identity().dimensions;
        let origin = component.min.map(|v| v.saturating_sub(padding));
        let end = [component.max[0].saturating_add(padding).min(dims[0]),
            component.max[1].saturating_add(padding).min(dims[1])];
        let dimensions = [end[0]-origin[0], end[1]-origin[1]];
        let count = dimensions[0] as usize * dimensions[1] as usize;
        if count > maximum_pixels { return Err(ForegroundError::Limit.into()); }
        budget.charge(count as u64 * 3)?;
        let mut pixels = super::filled(count, 0_u8)?;
        let mut allowed = super::filled(count, 0_u8)?;
        let mut membership = super::filled(count, 0_u8)?;
        for row in 0..dimensions[1] { for column in 0..dimensions[0] {
            budget.charge(4)?;
            let from = ((row+origin[1])*dims[0]+column+origin[0]) as usize;
            let to = (row*dimensions[0]+column) as usize;
            if self.frame.allowed()[from] != 0 {
                allowed[to] = 1; pixels[to] = self.frame.pixels()[from];
                membership[to] = u8::from(self.report.component_labels()[from] == region);
            }
        }}
        let mut bytes = reserve(256)?;
        bytes.extend_from_slice(b"fss/foreground-crop/reference/1\0");
        bytes.extend_from_slice(&self.report.digest()); integer(&mut bytes, u64::from(region));
        for n in origin.into_iter().chain(dimensions) { integer(&mut bytes, u64::from(n)); }
        budget.charge(count as u64 * 3)?;
        for data in [&pixels, &allowed, &membership] { bytes.extend_from_slice(&ContentDigest::sha256(data).bytes()); }
        let digest = ContentDigest::sha256(&bytes).bytes();
        budget.charge(0)?;
        Ok(ForegroundCrop { digest, report: self.report.digest(), region, source: self.report.source(),
            origin, dimensions, pixels, allowed, membership })
    }
}

/// A model input with an exact translation back to the full undistorted image.
/// Its permission/membership masks must travel with its pixels. A crop is not a new exposure.
pub struct ForegroundCrop {
    digest: [u8; 32], report: [u8; 32], region: u32, source: ForegroundSource,
    origin: [u32; 2], dimensions: [u32; 2], pixels: Vec<u8>, allowed: Vec<u8>, membership: Vec<u8>,
}
impl std::fmt::Debug for ForegroundCrop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForegroundCrop").field("dimensions", &self.dimensions).finish_non_exhaustive()
    }
}
impl ForegroundCrop {
    /// Exact crop-data and source/report identity.
    pub fn digest(&self) -> [u8; 32] { self.digest }
    /// Full input image, exposure, calibration and capture interval, not crop coordinates.
    pub fn source(&self) -> ForegroundSource { self.source }
    /// Integer origin in full-image pixel-edge coordinates.
    pub fn origin(&self) -> [u32; 2] { self.origin }
    /// Width and height of the tightly packed crop.
    pub fn dimensions(&self) -> [u32; 2] { self.dimensions }
    /// Full-range luma, zero at denied locations.
    pub fn pixels(&self) -> &[u8] { &self.pixels }
    /// Exact current permission mask; a zero intensity is not a permission signal.
    pub fn allowed(&self) -> &[u8] { &self.allowed }
    /// Exact pixels of the selected component, not its filled bounding rectangle.
    pub fn membership(&self) -> &[u8] { &self.membership }

    /// Translate an EXPLICIT external contact-model/annotation result to the existing
    /// association input. Visible contact is a supplied claim, never inferred here
    /// from the component bottom. The evidence record must bind this crop, source,
    /// contact model/review and coordinate interval; this function cannot authenticate it.
    pub fn prepare_contact(&self, evidence: [u8; 32], min: [f64; 2], max: [f64; 2],
        visible_contact: bool, budget: &mut WorkBudget<'_>) -> Result<PreparedForegroundContact, ForegroundPipelineError> {
        budget.charge(0)?;
        if [self.source.image.exposure, self.source.image.pixels, self.digest, self.report, [0;32]].contains(&evidence)
            || (0..2).any(|i| !min[i].is_finite() || !max[i].is_finite() || min[i] < 0.0
                || min[i] > max[i] || max[i] >= f64::from(self.dimensions[i])) {
            return Err(ForegroundPipelineError::InvalidInput);
        }
        let lower = min.map(|x| x.floor() as u32); let upper = max.map(|x| x.floor() as u32);
        let mut intersects_component = false;
        for y in lower[1]..=upper[1] { for x in lower[0]..=upper[0] {
            budget.charge(1)?;
            let index = (y*self.dimensions[0]+x) as usize;
            if self.allowed[index] == 0 { return Err(ForegroundPipelineError::InvalidInput); }
            intersects_component |= self.membership[index] != 0;
        }}
        if !intersects_component { return Err(ForegroundPipelineError::InvalidInput); }
        let pixel_min = [min[0]+f64::from(self.origin[0]), min[1]+f64::from(self.origin[1])];
        let pixel_max = [max[0]+f64::from(self.origin[0]), max[1]+f64::from(self.origin[1])];
        let detection = UnassignedContact { id: u64::from(self.region), evidence, pixel_min, pixel_max, visible_contact };
        budget.charge(0)?;
        Ok(PreparedForegroundContact { source: self.source, report: self.report, crop: self.digest, detection })
    }
}
/// An external contact claim with the full image/crop/region lineage still attached.
/// It has no track assignment and cannot activate or mutate the tracking service.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PreparedForegroundContact {
    /// Actual query exposure/calibration/capture basis required on the association frame.
    pub source: ForegroundSource,
    /// Complete foreground report, including all omissions and disturbance flags.
    pub report: [u8; 32],
    /// Exact model/annotation crop input.
    pub crop: [u8; 32],
    /// Existing unassigned-contact payload in FULL-image coordinates.
    pub detection: UnassignedContact,
}
