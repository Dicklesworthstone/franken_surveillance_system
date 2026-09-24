#![forbid(unsafe_code)]
//! Deterministic, model-free activity gating over already-governed image bytes.
//!
//! A gate measures sampled pixel change, not objects, intent, scene safety, or absence.
//! Neither a low score nor a skipped frame is a coverage witness. The caller owns
//! acquisition, permission checks, privacy projection, source retention, and scheduling.

use fss_core::{
    CanonicalEncode, CanonicalEncoder, ContentDigest, DigestAlgorithm, Generation, Sha256Hasher,
    SourceId, StreamGeneration,
};
use fss_tensor::MAX_STORAGE_BYTES;

use crate::preprocess::ImageBytes;
use crate::scalar_executor::{ExecBudget, ExecError, ScalarExecCx};

/// Hard ceiling on retained samples per gate, independent of caller budgets.
pub const MAX_ACTIVITY_SAMPLES: usize = 65_536;
/// Versioned algorithm domain, including integer RGB-to-luma and sampling semantics.
pub const ACTIVITY_DOMAIN: &str = "fss.reference.sampled_activity.v1";

/// Source and interpretation scope. A change invalidates the comparison baseline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityBasis {
    /// Stable source identity supplied by the acquiring owner.
    pub source: SourceId,
    /// Immutable stream generation; reconnects must use a new value.
    pub stream_generation: StreamGeneration,
    /// Generation of decoded pixels; must match `ImageBytes::generation`.
    pub decoder_generation: Generation,
    /// Exact policy basis supplied by the authorized caller.
    pub policy_digest: ContentDigest,
    /// Exact privacy projection/view basis of these pixels.
    pub projection_digest: ContentDigest,
}

impl ActivityBasis {
    /// Identifies the supplied scope, without attesting to authority or custody.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text("fss.reference.activity_basis.v1");
        self.source.encode_canonical(&mut e);
        self.stream_generation.encode_canonical(&mut e);
        self.decoder_generation.encode_canonical(&mut e);
        e.digest(self.policy_digest);
        e.digest(self.projection_digest);
        ContentDigest::sha256(&e.finish())
    }
}

/// Validated immutable sampling and decision parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivityConfig {
    sample_width: usize,
    sample_height: usize,
    pixel_delta: u8,
    changed_basis_points: u16,
}

impl ActivityConfig {
    /// Configures a nearest-sampled grid and inclusive change thresholds.
    /// The grid is capped to the source dimensions, so pixels are never duplicated.
    /// `pixel_delta` must be positive; the changed fraction is in `1..=10_000`.
    pub fn new(
        sample_width: usize,
        sample_height: usize,
        pixel_delta: u8,
        changed_basis_points: u16,
    ) -> Result<Self, ExecError> {
        let count = sample_width
            .checked_mul(sample_height)
            .ok_or_else(|| invalid("sample-grid size overflows"))?;
        if count == 0
            || count > MAX_ACTIVITY_SAMPLES
            || pixel_delta == 0
            || !(1..=10_000).contains(&changed_basis_points)
        {
            return Err(invalid("invalid sample grid or activity threshold"));
        }
        Ok(Self {
            sample_width,
            sample_height,
            pixel_delta,
            changed_basis_points,
        })
    }

    /// Identifies numerical semantics; execution budgets are deliberately excluded.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text(ACTIVITY_DOMAIN);
        e.u64(self.sample_width as u64);
        e.u64(self.sample_height as u64);
        e.u8(self.pixel_delta);
        e.u64(u64::from(self.changed_basis_points));
        ContentDigest::sha256(&e.finish())
    }
}

/// Borrowed observed pixels and their source sequence in the supplied scope.
#[derive(Clone, Copy, Debug)]
pub struct ActivityFrame<'a> {
    /// Already-governed HWC U8 pixels.
    pub image: ImageBytes<'a>,
    /// Source, decoder, policy, and privacy interpretation.
    pub basis: &'a ActivityBasis,
    /// Positive source sequence, strictly increasing within an unchanged basis.
    pub sequence: u64,
}

/// Why a frame establishes a baseline rather than producing a change score.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ActivityReset {
    /// No accepted observation has preceded this frame.
    FirstFrame = 1,
    /// Source, stream, decoder, policy, or projection changed.
    BasisChanged = 2,
    /// Pixel dimensions or channel layout changed.
    ShapeChanged = 3,
    /// Source sequence was not adjacent to the previous observation.
    SequenceGap = 4,
    /// A skipped, rejected, or cancelled observation invalidated the baseline.
    ObservationGap = 5,
}

/// Explicit reasons for not evaluating pixels; none is equivalent to inactivity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ActivitySkip {
    /// Pixel/work admission failed before reading or copying image bytes.
    Budget = 1,
    /// The owner denied the observation; no pixels need be supplied.
    Denied = 2,
    /// The owner reported obscuration; no normal change score is manufactured.
    Obscured = 3,
    /// No frame was observed.
    Unobserved = 4,
}

/// A measured change decision, a new baseline, or an explicit missing evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivityDecision {
    /// Both inclusive configured thresholds were met on the sampled grid.
    Changed,
    /// The sampled change fraction was below threshold, not proof of absence.
    BelowThreshold,
    /// No comparable previous frame exists.
    BaselineOnly(ActivityReset),
    /// No pixel evaluation was performed.
    NotEvaluated(ActivitySkip),
}

/// Exact integer statistics over a pair of comparable sampled frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivityMeasurement {
    /// Actual sampled grid width, capped to source width.
    pub sample_width: usize,
    /// Actual sampled grid height, capped to source height.
    pub sample_height: usize,
    /// Number of samples whose absolute luma delta meets the pixel threshold.
    pub changed_samples: usize,
    /// Sum of absolute luma deltas, before any rounding or normalization.
    pub absolute_delta_sum: u64,
    /// Floor of the measured changed fraction times 10,000, for display only.
    pub changed_basis_points: u16,
    /// Bounding XYXY rectangle in sample-grid coordinates, not dense source coverage.
    pub changed_sample_box: Option<[usize; 4]>,
}

/// Replayable local computation receipt; not an authority or negative-evidence witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityReceipt {
    basis: ContentDigest,
    config: ContentDigest,
    sequence: u64,
    decision: ActivityDecision,
    input: Option<ContentDigest>,
    previous_input: Option<ContentDigest>,
    measurement: Option<ActivityMeasurement>,
    admitted_work: u64,
    pixel_buffer_bytes: usize,
}

impl ActivityReceipt {
    /// Returns the explicit evaluation disposition.
    #[must_use]
    pub const fn decision(&self) -> ActivityDecision {
        self.decision
    }
    /// Returns statistics only when two comparable frames were evaluated.
    #[must_use]
    pub const fn measurement(&self) -> Option<ActivityMeasurement> {
        self.measurement
    }
    /// Returns the observed source-pixel identity, absent on every skip.
    #[must_use]
    pub const fn input_digest(&self) -> Option<ContentDigest> {
        self.input
    }
    /// Returns the exact previous input used in a measured comparison.
    #[must_use]
    pub const fn previous_input_digest(&self) -> Option<ContentDigest> {
        self.previous_input
    }
    /// Returns the source and interpretation basis identity.
    #[must_use]
    pub const fn basis_digest(&self) -> ContentDigest {
        self.basis
    }
    /// Returns the source sequence identified by this receipt.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Returns admitted logical work units; zero when no pixels were evaluated.
    #[must_use]
    pub const fn admitted_work(&self) -> u64 {
        self.admitted_work
    }
    /// Returns the logical input/current/prior sample-buffer bound.
    #[must_use]
    pub const fn pixel_buffer_bytes(&self) -> usize {
        self.pixel_buffer_bytes
    }
    /// Activity scoring never certifies semantic absence, even for an unchanged frame.
    #[must_use]
    pub const fn supports_absence_claim(&self) -> bool {
        false
    }

    /// Binds the complete decision, both inputs, configuration, measurements, and costs.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text("fss.reference.activity_receipt.v1");
        e.digest(self.basis);
        e.digest(self.config);
        e.u64(self.sequence);
        match self.decision {
            ActivityDecision::Changed => e.u8(1),
            ActivityDecision::BelowThreshold => e.u8(2),
            ActivityDecision::BaselineOnly(reason) => {
                e.u8(3);
                e.u8(reason as u8);
            }
            ActivityDecision::NotEvaluated(reason) => {
                e.u8(4);
                e.u8(reason as u8);
            }
        }
        for input in [self.input, self.previous_input] {
            e.bool(input.is_some());
            if let Some(digest) = input {
                e.digest(digest);
            }
        }
        e.bool(self.measurement.is_some());
        if let Some(m) = self.measurement {
            e.u64(m.sample_width as u64);
            e.u64(m.sample_height as u64);
            e.u64(m.changed_samples as u64);
            e.u64(m.absolute_delta_sum);
            e.u64(u64::from(m.changed_basis_points));
            e.bool(m.changed_sample_box.is_some());
            if let Some(rectangle) = m.changed_sample_box {
                for coordinate in rectangle {
                    e.u64(coordinate as u64);
                }
            }
        }
        e.u64(self.admitted_work);
        e.u64(self.pixel_buffer_bytes as u64);
        ContentDigest::sha256(&e.finish())
    }
}

struct Baseline {
    dims: [usize; 3],
    pixels: Vec<u8>,
    digest: ContentDigest,
}

struct GateState {
    basis: ActivityBasis,
    sequence: u64,
    baseline: Option<Baseline>,
}

/// One bounded reference gate. Use one instance per independently scheduled source.
/// Baselines never survive source/interpretation changes, sequence gaps, or skips.
/// Errors and cancellation discard the comparison baseline without advancing sequence.
pub struct ActivityGate {
    config: ActivityConfig,
    state: Option<GateState>,
}

impl ActivityGate {
    /// Creates an empty gate with validated immutable configuration.
    #[must_use]
    pub const fn new(config: ActivityConfig) -> Self {
        Self {
            config,
            state: None,
        }
    }

    /// Reports the number of retained luma samples, bounded by `MAX_ACTIVITY_SAMPLES`.
    #[must_use]
    pub fn retained_samples(&self) -> usize {
        self.state
            .as_ref()
            .and_then(|s| s.baseline.as_ref())
            .map_or(0, |b| b.pixels.len())
    }

    /// Observes admitted pixels. Budget refusal becomes a truthful `NotEvaluated` receipt.
    /// Invalid metadata, stale sequences, and cancellation return errors, never low scores.
    pub fn observe(
        &mut self,
        frame: ActivityFrame<'_>,
        budget: ExecBudget,
        cx: &ScalarExecCx,
    ) -> Result<ActivityReceipt, ExecError> {
        match self.evaluate(frame, budget, cx) {
            Ok((receipt, state)) => {
                self.state = Some(state);
                Ok(receipt)
            }
            Err(error) => {
                if let Some(state) = &mut self.state {
                    state.baseline = None;
                }
                Err(error)
            }
        }
    }

    /// Records a denied, obscured, unobserved, or explicitly budget-skipped sequence.
    /// This API takes no image bytes and always invalidates the comparison baseline.
    pub fn skip(
        &mut self,
        basis: &ActivityBasis,
        sequence: u64,
        reason: ActivitySkip,
    ) -> Result<ActivityReceipt, ExecError> {
        match self.skipped(basis, sequence, reason) {
            Ok((receipt, state)) => {
                self.state = Some(state);
                Ok(receipt)
            }
            Err(error) => {
                if let Some(state) = &mut self.state {
                    state.baseline = None;
                }
                Err(error)
            }
        }
    }

    fn check_sequence(&self, basis: &ActivityBasis, sequence: u64) -> Result<(), ExecError> {
        if sequence == 0 {
            return Err(invalid("source sequence must be positive"));
        }
        if let Some(state) = &self.state
            && state.basis == *basis
            && sequence <= state.sequence
        {
            return Err(invalid(
                "source sequence must strictly increase within its basis",
            ));
        }
        Ok(())
    }

    fn skipped(
        &self,
        basis: &ActivityBasis,
        sequence: u64,
        reason: ActivitySkip,
    ) -> Result<(ActivityReceipt, GateState), ExecError> {
        self.check_sequence(basis, sequence)?;
        Ok((
            ActivityReceipt {
                basis: basis.digest(),
                config: self.config.digest(),
                sequence,
                decision: ActivityDecision::NotEvaluated(reason),
                input: None,
                previous_input: None,
                measurement: None,
                admitted_work: 0,
                pixel_buffer_bytes: 0,
            },
            GateState {
                basis: basis.clone(),
                sequence,
                baseline: None,
            },
        ))
    }

    fn evaluate(
        &self,
        frame: ActivityFrame<'_>,
        budget: ExecBudget,
        cx: &ScalarExecCx,
    ) -> Result<(ActivityReceipt, GateState), ExecError> {
        cx.checkpoint("activity:admit")?;
        self.check_sequence(frame.basis, frame.sequence)?;
        let image = frame.image;
        if image.generation != frame.basis.decoder_generation {
            return Err(ExecError::GenerationMismatch {
                expected: frame.basis.decoder_generation,
                actual: image.generation,
                tensor_name: "activity_input".to_owned(),
            });
        }
        let dims = [image.height, image.width, image.channels];
        if image.height == 0 || image.width == 0 || !matches!(image.channels, 1 | 3) {
            return Err(invalid(
                "expected positive HWC dimensions with one or three channels",
            ));
        }
        let input_bytes = image
            .height
            .checked_mul(image.width)
            .and_then(|v| v.checked_mul(image.channels))
            .ok_or_else(|| invalid("activity input size overflows"))?;
        if input_bytes > MAX_STORAGE_BYTES || image.bytes.len() != input_bytes {
            return Err(invalid("activity pixels exceed their size contract"));
        }
        let sw = image.width.min(self.config.sample_width);
        let sh = image.height.min(self.config.sample_height);
        // Config and input ceilings make all following counts/products bounded.
        let count = sw * sh;
        let work = input_bytes as u64 + (count as u64) * 32;
        let bytes = input_bytes + count + self.retained_samples();
        if work > budget.max_macs || bytes > budget.max_bytes {
            cx.checkpoint("activity:budget-refusal")?;
            return self.skipped(frame.basis, frame.sequence, ActivitySkip::Budget);
        }
        let basis_digest = frame.basis.digest();
        let mut header = CanonicalEncoder::new();
        header.text("fss.reference.activity_pixels.v1");
        header.digest(basis_digest);
        header.u64(frame.sequence);
        for dim in dims {
            header.u64(dim as u64);
        }
        let mut hasher = Sha256Hasher::new();
        hasher.update(&header.finish());
        for chunk in image.bytes.chunks(4096) {
            cx.checkpoint("activity:hash")?;
            hasher.update(chunk);
        }
        let digest = ContentDigest::new(
            DigestAlgorithm::Sha256,
            hasher
                .finalize()
                .map_err(|_| invalid("activity digest length overflows"))?,
        );
        let mut samples = Vec::new();
        samples
            .try_reserve_exact(count)
            .map_err(|_| invalid("activity sample allocation failed"))?;
        for y in 0..sh {
            for x in 0..sw {
                if (y * sw + x).is_multiple_of(1024) {
                    cx.checkpoint("activity:sample")?;
                }
                let sy = ((y as u128) * (image.height as u128) / sh as u128) as usize;
                let sx = ((x as u128) * (image.width as u128) / sw as u128) as usize;
                let offset = (sy * image.width + sx) * image.channels;
                let luma = if image.channels == 1 {
                    image.bytes[offset]
                } else {
                    // Fixed U8 reference transform: round((77R + 150G + 29B) / 256).
                    let r = u32::from(image.bytes[offset]);
                    let g = u32::from(image.bytes[offset + 1]);
                    let b = u32::from(image.bytes[offset + 2]);
                    ((77 * r + 150 * g + 29 * b + 128) >> 8) as u8
                };
                samples.push(luma);
            }
        }
        let reset = match &self.state {
            None => Some(ActivityReset::FirstFrame),
            Some(state) if state.basis != *frame.basis => Some(ActivityReset::BasisChanged),
            Some(state) if state.sequence.checked_add(1) != Some(frame.sequence) => {
                Some(ActivityReset::SequenceGap)
            }
            Some(state) => match &state.baseline {
                None => Some(ActivityReset::ObservationGap),
                Some(baseline) if baseline.dims != dims => Some(ActivityReset::ShapeChanged),
                Some(_) => None,
            },
        };
        let mut previous_input = None;
        let mut measurement = None;
        let decision = if let Some(reason) = reset {
            ActivityDecision::BaselineOnly(reason)
        } else {
            let baseline = self
                .state
                .as_ref()
                .and_then(|s| s.baseline.as_ref())
                .ok_or_else(|| invalid("missing comparable activity baseline"))?;
            if baseline.pixels.len() != samples.len() {
                return Err(invalid("activity sample-grid mismatch"));
            }
            let m = compare(
                &baseline.pixels,
                &samples,
                sw,
                sh,
                self.config.pixel_delta,
                cx,
            )?;
            let changed = (m.changed_samples as u64) * 10_000
                >= u64::from(self.config.changed_basis_points) * (count as u64);
            previous_input = Some(baseline.digest);
            measurement = Some(m);
            if changed {
                ActivityDecision::Changed
            } else {
                ActivityDecision::BelowThreshold
            }
        };
        cx.checkpoint("activity:publish")?;
        Ok((
            ActivityReceipt {
                basis: basis_digest,
                config: self.config.digest(),
                sequence: frame.sequence,
                decision,
                input: Some(digest),
                previous_input,
                measurement,
                admitted_work: work,
                pixel_buffer_bytes: bytes,
            },
            GateState {
                basis: frame.basis.clone(),
                sequence: frame.sequence,
                baseline: Some(Baseline {
                    dims,
                    pixels: samples,
                    digest,
                }),
            },
        ))
    }
}

fn compare(
    prior: &[u8],
    current: &[u8],
    sw: usize,
    sh: usize,
    threshold: u8,
    cx: &ScalarExecCx,
) -> Result<ActivityMeasurement, ExecError> {
    let mut changed = 0_usize;
    let mut sum = 0_u64;
    let mut bounds = [sw, sh, 0, 0];
    for (index, (&before, &after)) in prior.iter().zip(current).enumerate() {
        if index % 1024 == 0 {
            cx.checkpoint("activity:compare")?;
        }
        let delta = before.abs_diff(after);
        sum += u64::from(delta);
        if delta >= threshold {
            changed += 1;
            let x = index % sw;
            let y = index / sw;
            bounds[0] = bounds[0].min(x);
            bounds[1] = bounds[1].min(y);
            bounds[2] = bounds[2].max(x + 1);
            bounds[3] = bounds[3].max(y + 1);
        }
    }
    Ok(ActivityMeasurement {
        sample_width: sw,
        sample_height: sh,
        changed_samples: changed,
        absolute_delta_sum: sum,
        changed_basis_points: ((changed as u64) * 10_000 / (current.len() as u64)) as u16,
        changed_sample_box: (changed > 0).then_some(bounds),
    })
}

fn invalid(reason: &str) -> ExecError {
    ExecError::ShapeMismatch {
        node_id: "activity".to_owned(),
        op_id: ACTIVITY_DOMAIN,
        reason: reason.to_owned(),
    }
}
