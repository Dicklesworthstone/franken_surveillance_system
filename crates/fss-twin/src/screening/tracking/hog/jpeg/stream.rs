#![forbid(unsafe_code)]
//! Exact stream-frame lineage through native learned inference and resumable zones.
//! Framing, capture-time admission and source custody remain independent contracts.

use super::{JpegHogCompletion, JpegHogError, JpegHogPipeline, JpegHogProgress, JpegHogStage};
use crate::mjpeg::JpegBackground;
use crate::mjpeg::stream::{FramedQuery, StreamFrameReceipt};
use crate::rectification::RectificationPlan;
use crate::screened_mjpeg::JpegScreeningQuery;
use crate::screening::{ScreeningStamp, StallObservation};
use fss_codec_mjpeg::DecodeBudget;
use fss_codec_mjpeg::stream::StreamBasis;
use fss_core::ContentDigest;
use fss_geometry::{GeometryError, WorkBudget};

/// A refused new source leaves both the stream cursor and learned owner unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FramedHogError {
    /// Stream, generation, ordinal stamp, encoded binding or initial owner differs.
    BasisMismatch,
    /// A frame ordinal repeated/regressed, or its source range overlaps prior input.
    OutOfOrder,
    /// The existing JPEG owner refused; accepted work remains available on resume.
    Analysis(JpegHogError),
    /// Boundary work/cancellation refused before accepting a new frame.
    Work(GeometryError),
}
impl std::fmt::Display for FramedHogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::BasisMismatch => "framed HOG source basis mismatch",
            Self::OutOfOrder => "framed HOG source range or ordinal did not advance",
            Self::Analysis(_) => "framed HOG analysis owner refused",
            Self::Work(_) => "framed HOG boundary work interrupted",
        })
    }
}
impl std::error::Error for FramedHogError {}
impl From<JpegHogError> for FramedHogError {
    fn from(error: JpegHogError) -> Self {
        Self::Analysis(error)
    }
}

/// Full stream-to-computation linkage, not an archive publication or coverage witness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FramedHogCompletion {
    /// Original stream generation, ordinal, compressed hash and half-open byte range.
    pub source: StreamFrameReceipt,
    /// Existing exact JPEG, scan, anonymous tracking and zone computation roots.
    pub analysis: JpegHogCompletion,
    /// Domain-separated fingerprint of every source field and all four analysis roots.
    pub digest: [u8; 32],
}

/// Single bounded owner connecting already framed MJPEG to the existing learned path.
///
/// The caller retains the actual FramedJpeg bytes and admits capture times separately.
/// This owner stores only the current source receipt and existing pipeline state. It
/// never reads more stream bytes, invents timestamps, acknowledges semantic custody,
/// or turns a complete computation into an effect. Gapped input is not continuity.
pub struct FramedJpegHogPipeline {
    pipeline: JpegHogPipeline,
    basis: StreamBasis,
    source: Option<StreamFrameReceipt>,
    completed: Option<FramedHogCompletion>,
}
impl FramedJpegHogPipeline {
    /// Bind a fresh learned owner to exactly one independently admitted stream.
    /// A started owner or different screening generation cannot be relabelled.
    pub fn new(
        pipeline: JpegHogPipeline,
        basis: StreamBasis,
        budget: &mut WorkBudget<'_>,
    ) -> Result<Self, FramedHogError> {
        budget.charge(1).map_err(FramedHogError::Work)?;
        if basis.source == [0; 32]
            || basis.generation == 0
            || pipeline.stage() != JpegHogStage::AwaitingImage
            || pipeline.zones.generation != basis.generation
        {
            return Err(FramedHogError::BasisMismatch);
        }
        Ok(Self {
            pipeline,
            basis,
            source: None,
            completed: None,
        })
    }
    /// Frozen source basis. No mutable escape can swap the inner owner or generation.
    pub fn basis(&self) -> StreamBasis {
        self.basis
    }
    /// Existing stage, image, scan, tracking and zone accessors, without mutation.
    pub fn pipeline(&self) -> &JpegHogPipeline {
        &self.pipeline
    }
    /// Last accepted frame's original range, including during inference/zone pressure.
    pub fn source_receipt(&self) -> Option<StreamFrameReceipt> {
        self.source
    }
    /// Present only when the CURRENT accepted frame completed every requested stage.
    pub fn completion(&self) -> Option<FramedHogCompletion> {
        self.completed
    }
    /// Keep the existing independent health watchdog available during model pressure.
    pub fn poll(&mut self, now_ns: u64) -> Result<StallObservation, FramedHogError> {
        Ok(self.pipeline.poll(now_ns)?)
    }

    /// Accept one completed framer output, preserving exact source and capture identities.
    ///
    /// The sequence must equal the frame ordinal, but ordinal/arrival is NOT capture
    /// time. Ordinal gaps remain visible to the existing health-chain gate; skipped
    /// bytes cannot prove coverage. Errors do not consume the offered frame. Pending
    /// means it WAS accepted: retain this owner and resume before offering another.
    /// No fallible work follows successful inner acceptance. The fixed boundary charge
    /// prepays the bounded completion fingerprint, even when completion is deferred.
    #[allow(clippy::too_many_arguments)]
    pub fn observe(
        &mut self,
        background: Option<&JpegBackground>,
        plan: &RectificationPlan,
        query: FramedQuery<'_>,
        stamp: ScreeningStamp,
        decode: &mut DecodeBudget<'_>,
        rectification: &mut WorkBudget<'_>,
        foreground: &mut WorkBudget<'_>,
        health: &mut WorkBudget<'_>,
        inference: &mut WorkBudget<'_>,
        downstream: &mut WorkBudget<'_>,
    ) -> Result<JpegHogProgress, FramedHogError> {
        if !matches!(
            self.pipeline.stage(),
            JpegHogStage::AwaitingImage | JpegHogStage::Complete
        ) {
            return Err(JpegHogError::PendingAnalysis.into());
        }
        health.charge(1024).map_err(FramedHogError::Work)?;
        let frame = query.frame;
        if query.expected_stream != self.basis
            || frame.basis() != self.basis
            || stamp.stream_generation != self.basis.generation
            || stamp.sequence != frame.ordinal()
            || query.binding.encoded_sha256 != frame.encoded_sha256()
        {
            return Err(FramedHogError::BasisMismatch);
        }
        let source = StreamFrameReceipt {
            basis: frame.basis(),
            ordinal: frame.ordinal(),
            byte_range: frame.byte_range(),
            encoded_sha256: frame.encoded_sha256(),
        };
        if self.source.is_some_and(|old| {
            source.ordinal <= old.ordinal || source.byte_range[0] < old.byte_range[1]
        }) {
            return Err(FramedHogError::OutOfOrder);
        }
        let progress = self.pipeline.observe(
            background,
            plan,
            JpegScreeningQuery {
                bytes: frame.bytes(),
                mask: query.mask,
                binding: query.binding,
                capture: query.capture,
                foreground_policy: query.policy,
                decode_limits: query.limits,
                stamp,
                redaction: None,
            },
            decode,
            rectification,
            foreground,
            health,
            inference,
            downstream,
        )?;
        self.source = Some(source);
        self.completed = match progress {
            JpegHogProgress::Complete(analysis) => Some(completion(source, analysis)),
            JpegHogProgress::Pending { .. } => None,
        };
        Ok(progress)
    }
    /// Resume the accepted source only. Complete retries are allocation/work-free and
    /// preserve the same stream-linked root, without rescanning or consuming an ordinal.
    pub fn resume(
        &mut self,
        inference: &mut WorkBudget<'_>,
        downstream: &mut WorkBudget<'_>,
    ) -> Result<JpegHogProgress, FramedHogError> {
        if let Some(done) = self.completed {
            return Ok(JpegHogProgress::Complete(done.analysis));
        }
        let source = self
            .source
            .ok_or(FramedHogError::Analysis(JpegHogError::NoObservation))?;
        let progress = self.pipeline.resume(inference, downstream)?;
        if let JpegHogProgress::Complete(analysis) = progress {
            self.completed = Some(completion(source, analysis));
        }
        Ok(progress)
    }
}

fn completion(source: StreamFrameReceipt, analysis: JpegHogCompletion) -> FramedHogCompletion {
    // Fixed-width little-endian local receipt, not a new canonical durable format.
    let mut bytes = [0_u8; 256];
    bytes[..32].copy_from_slice(&source.basis.source);
    bytes[32..40].copy_from_slice(&source.basis.generation.to_le_bytes());
    bytes[40..48].copy_from_slice(&source.ordinal.to_le_bytes());
    bytes[48..56].copy_from_slice(&source.byte_range[0].to_le_bytes());
    bytes[56..64].copy_from_slice(&source.byte_range[1].to_le_bytes());
    bytes[64..96].copy_from_slice(&source.encoded_sha256);
    bytes[96..128].copy_from_slice(&analysis.image);
    bytes[128..160].copy_from_slice(&analysis.scan);
    bytes[160..192].copy_from_slice(&analysis.tracking);
    bytes[192..224].copy_from_slice(&analysis.zones);
    let tag = b"fss/framed-jpeg-hog/complete/1\0";
    bytes[224..224 + tag.len()].copy_from_slice(tag);
    FramedHogCompletion {
        source,
        analysis,
        digest: ContentDigest::sha256(&bytes).bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn values() -> (StreamFrameReceipt, JpegHogCompletion) {
        (
            StreamFrameReceipt {
                basis: StreamBasis {
                    source: [1; 32],
                    generation: 2,
                },
                ordinal: 3,
                byte_range: [10, 20],
                encoded_sha256: [4; 32],
            },
            JpegHogCompletion {
                image: [5; 32],
                scan: [6; 32],
                tracking: [7; 32],
                zones: [8; 32],
            },
        )
    }
    #[test]
    fn complete_receipt_has_an_independent_fixed_width_golden() {
        let (source, analysis) = values();
        assert_eq!(
            completion(source, analysis).digest,
            [
                53, 243, 122, 198, 60, 24, 228, 182, 249, 70, 85, 41, 162, 220, 171, 69, 228, 6,
                192, 231, 109, 231, 178, 93, 116, 37, 28, 45, 247, 31, 249, 47
            ]
        );
    }
    #[test]
    fn every_source_field_and_analysis_root_changes_the_fingerprint() {
        let (source, analysis) = values();
        let expected = completion(source, analysis).digest;
        for field in 0..10 {
            let (mut s, mut a) = values();
            match field {
                0 => s.basis.source[0] ^= 1,
                1 => s.basis.generation += 1,
                2 => s.ordinal += 1,
                3 => s.byte_range[0] += 1,
                4 => s.byte_range[1] += 1,
                5 => s.encoded_sha256[0] ^= 1,
                6 => a.image[0] ^= 1,
                7 => a.scan[0] ^= 1,
                8 => a.tracking[0] ^= 1,
                _ => a.zones[0] ^= 1,
            }
            assert_ne!(completion(s, a).digest, expected);
        }
    }
}
