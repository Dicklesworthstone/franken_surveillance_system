#![forbid(unsafe_code)]
//! Conservative selection of decoded output on its retained source-time coordinates.
//!
//! This pure core receives metadata from an already verified decode owner. It never reads
//! pixels, changes a capture interval, converts a clock, or grants disclosure authority.
//! A closed capture interval must be wholly inside or wholly outside the requested half-open
//! window. An uncertain boundary crossing refuses the whole selection, including an otherwise
//! usable prefix. Inter-predicted preroll may still be decoded by the owner but is not selected.
//!
//! The caller supplies every decoded frame in the decoder's display order, then calls
//! [`FrameWindowSelector::finish`] only after that exact range reaches successful EOF. The
//! receipt binds a bounded conditional selection, not continuous coverage or file durability.
//! Its projection may be reported as output completion only after the output owner has synced
//! its complete selected bytes. Current retained timing is an operator assumption; FLDT
//! grants, source-side payment-mask attestations and custody publication remain separate owners.

use fss_core::{
    CanonicalEncode, CanonicalEncoder, CaptureInterval, ClockBasis, ContentDigest,
    DigestAlgorithm, SensorCapsule, SensorId, Sha256Hasher, StreamId, TimestampNs,
};

/// Hard bound shared with the admitted non-streaming native video range profile.
pub const MAX_FRAME_WINDOW_SEGMENTS: usize = 1024;
/// Canonical request identity, including source range, declared time provenance and clock basis.
pub const FRAME_WINDOW_REQUEST_DOMAIN: &str = "fss.decoded_output_window_request.v1";
/// Complete ordered decisions plus counts; never an output-publication or coverage receipt.
pub const FRAME_WINDOW_SELECTION_DOMAIN: &str = "fss.decoded_output_window_selection.v1";
const MAX_CAPSULE_BYTES: usize = 1024;

/// An explicit, nonempty half-open window on the source's existing clock coordinates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodedOutputWindow {
    start: TimestampNs,
    end: TimestampNs,
    clock_basis: ClockBasis,
}

impl DecodedOutputWindow {
    /// Validate ordering and a representable positive signed-nanosecond duration.
    pub fn new(
        start: TimestampNs,
        end: TimestampNs,
        clock_basis: ClockBasis,
    ) -> Result<Self, FrameWindowError> {
        if end.0.checked_sub(start.0).is_none_or(|span| span <= 0) {
            return Err(FrameWindowError::InvalidWindow);
        }
        Ok(Self {
            start,
            end,
            clock_basis,
        })
    }

    /// Inclusive source-coordinate lower bound.
    #[must_use]
    pub const fn start(self) -> TimestampNs {
        self.start
    }

    /// Exclusive source-coordinate upper bound.
    #[must_use]
    pub const fn end(self) -> TimestampNs {
        self.end
    }

    /// Exact declared basis required even for frames excluded from the window.
    #[must_use]
    pub const fn clock_basis(self) -> ClockBasis {
        self.clock_basis
    }
}

/// Existing retained-import timing provenance. This does not authenticate a clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameWindowTimeProvenance {
    /// Capture coordinates are unavailable. A broad interval cannot promote this to usable time.
    Unknown,
    /// Retained explicit operator timing assumptions, preserved without narrowing uncertainty.
    OperatorAssumption,
}

/// Independent pins obtained from the current retained import owner before output begins.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameWindowSource {
    /// Exact import identity, never a path or an implicit latest source.
    pub import_identity: ContentDigest,
    /// Exact completed import publication root.
    pub import_root: ContentDigest,
    /// First requested access unit, including any decoded dependency preroll.
    pub first_segment: u64,
    /// Nonrefillable source/decision bound, including any codec-skipped RASL access units.
    pub segment_count: usize,
    /// Current retained manifest's explicit source-time provenance.
    pub time_provenance: FrameWindowTimeProvenance,
}

/// Complete metadata decision; it does not establish that selected media was written or synced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameWindowReceipt {
    /// Exact source, range, window, clock and timing-assumption identity.
    pub request_digest: ContentDigest,
    /// Ordered included/excluded capsule decisions, request and terminal summary.
    pub selection_digest: ContentDigest,
    /// Every decoded output examined, including excluded preroll and postroll.
    pub observed_frames: u64,
    /// Fully contained frames selected for output.
    pub selected_frames: u64,
    /// Wholly disjoint decoded frames excluded from output.
    pub skipped_frames: u64,
    /// Envelope of selected capture intervals; gaps inside it are not filled or certified.
    pub selected_capture: CaptureInterval,
}

/// Payload-free refusal. Any observation refusal permanently fences its selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameWindowError {
    /// Empty, inverted or overflowing half-open source-coordinate request.
    InvalidWindow,
    /// Invalid source digests, zero/excessive count, or overflowing segment range.
    InvalidSource,
    /// The retained import has no usable, explicit timing assumption.
    UnknownTime,
    /// A source capsule uses another clock basis, including an excluded capsule.
    ClockMismatch,
    /// Malformed capture bounds, frame count, source bytes or metadata identity.
    InvalidCapsule,
    /// Capsule bytes disagree with their independent pin, or source scope changed.
    SourceMismatch,
    /// One source segment was offered more than once, even at a new output ordinal.
    DuplicateSegment,
    /// Display-order output indices are not the exact contiguous sequence from zero.
    OutputOrder,
    /// A conservative capture interval crosses a requested boundary.
    BoundaryUncertain,
    /// A source segment or observation exceeds the requested bounded range.
    Limit,
    /// Owner cancellation was observed before a bounded metadata phase or finalization.
    Cancelled,
    /// An earlier refusal made this selection permanently unsuccessful.
    Fenced,
    /// The owner's complete decoded count does not equal the observed display-order count.
    IncompleteRange,
    /// No frame was fully contained; no successful empty export is produced.
    EmptySelection,
}

impl std::fmt::Display for FrameWindowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidWindow => "invalid decoded output window",
            Self::InvalidSource => "invalid decoded output source range",
            Self::UnknownTime => "decoded output window requires retained timing assumptions",
            Self::ClockMismatch => "decoded output window clock basis mismatch",
            Self::InvalidCapsule => "invalid decoded output capsule metadata",
            Self::SourceMismatch => "decoded output capsule identity or source scope mismatch",
            Self::DuplicateSegment => "duplicate decoded output source segment",
            Self::OutputOrder => "decoded output display order mismatch",
            Self::BoundaryUncertain => "decoded output capture interval crosses window boundary",
            Self::Limit => "decoded output window source or frame allowance exceeded",
            Self::Cancelled => "decoded output window cancelled",
            Self::Fenced => "decoded output window fenced after an earlier refusal",
            Self::IncompleteRange => "decoded output window range is incomplete",
            Self::EmptySelection => "decoded output window selected no frames",
        })
    }
}
impl std::error::Error for FrameWindowError {}

/// O(1) per-frame work, fixed duplicate-index scratch, and one small metadata encoding.
///
/// No frame array or pixel buffer is retained. Stream and sensor IDs are fixed by the first
/// independently pinned capsule. Segment order may differ from display order; capture time
/// may move backwards, and neither is used to stop examining the remaining range early.
#[derive(Debug)]
pub struct FrameWindowSelector {
    window: DecodedOutputWindow,
    source: FrameWindowSource,
    request_digest: ContentDigest,
    decisions: Sha256Hasher,
    seen_segments: [u64; MAX_FRAME_WINDOW_SEGMENTS / 64],
    scope: Option<(SensorId, StreamId)>,
    observed: u64,
    selected: u64,
    selected_capture: Option<CaptureInterval>,
    failed: bool,
}

impl FrameWindowSelector {
    /// Admit source pins and request before receiving frames or creating an output file.
    pub fn new(
        window: DecodedOutputWindow,
        source: FrameWindowSource,
    ) -> Result<Self, FrameWindowError> {
        if !(1..=MAX_FRAME_WINDOW_SEGMENTS).contains(&source.segment_count)
            || source
                .first_segment
                .checked_add(source.segment_count as u64)
                .is_none()
            || !valid_digest(source.import_identity)
            || !valid_digest(source.import_root)
        {
            return Err(FrameWindowError::InvalidSource);
        }
        if source.time_provenance != FrameWindowTimeProvenance::OperatorAssumption {
            return Err(FrameWindowError::UnknownTime);
        }
        let mut request = CanonicalEncoder::new();
        request.text(FRAME_WINDOW_REQUEST_DOMAIN);
        request.i128(window.start.0);
        request.i128(window.end.0);
        request.text(window.clock_basis.as_str());
        request.digest(source.import_identity);
        request.digest(source.import_root);
        request.u64(source.first_segment);
        request.u64(source.segment_count as u64);
        request.text("operator_assumption");
        let request_digest = ContentDigest::sha256(&request.finish());
        let mut decisions = Sha256Hasher::new();
        decisions.update(FRAME_WINDOW_SELECTION_DOMAIN.as_bytes());
        decisions.update(&[0]);
        decisions.update(&request_digest.bytes());
        Ok(Self {
            window,
            source,
            request_digest,
            decisions,
            seen_segments: [0; MAX_FRAME_WINDOW_SEGMENTS / 64],
            scope: None,
            observed: 0,
            selected: 0,
            selected_capture: None,
            failed: false,
        })
    }

    /// Inspect one source-pinned decoded frame before hashing its planes or encoding it.
    ///
    /// Returns true only when its entire closed capture interval is inside the half-open
    /// requested window. `cancelled` is the current owning context's cancellation probe.
    pub fn observe(
        &mut self,
        output_index: u64,
        segment_index: u64,
        capsule: &SensorCapsule,
        expected_capsule_digest: ContentDigest,
        cancelled: bool,
    ) -> Result<bool, FrameWindowError> {
        if self.failed {
            return Err(FrameWindowError::Fenced);
        }
        let result = self.observe_inner(
            output_index,
            segment_index,
            capsule,
            expected_capsule_digest,
            cancelled,
        );
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn observe_inner(
        &mut self,
        output_index: u64,
        segment_index: u64,
        capsule: &SensorCapsule,
        expected_capsule_digest: ContentDigest,
        cancelled: bool,
    ) -> Result<bool, FrameWindowError> {
        if cancelled {
            return Err(FrameWindowError::Cancelled);
        }
        if self.observed >= self.source.segment_count as u64 {
            return Err(FrameWindowError::Limit);
        }
        if output_index != self.observed {
            return Err(FrameWindowError::OutputOrder);
        }
        let offset = segment_index
            .checked_sub(self.source.first_segment)
            .filter(|offset| *offset < self.source.segment_count as u64)
            .ok_or(FrameWindowError::Limit)? as usize;
        let bit = 1_u64 << (offset % 64);
        if self.seen_segments[offset / 64] & bit != 0 {
            return Err(FrameWindowError::DuplicateSegment);
        }
        if capsule.clock_basis != self.window.clock_basis {
            return Err(FrameWindowError::ClockMismatch);
        }
        if capsule.capture.earliest > capsule.capture.latest
            || capsule.frame_count != 1
            || capsule.source_bytes == 0
            || !valid_digest(capsule.source_digest)
            || !valid_digest(expected_capsule_digest)
        {
            return Err(FrameWindowError::InvalidCapsule);
        }
        let bytes = capsule
            .try_canonical_bytes()
            .map_err(|_| FrameWindowError::InvalidCapsule)?;
        if bytes.len() > MAX_CAPSULE_BYTES {
            return Err(FrameWindowError::InvalidCapsule);
        }
        if ContentDigest::sha256(&bytes) != expected_capsule_digest {
            return Err(FrameWindowError::SourceMismatch);
        }
        if let Some((sensor, stream)) = &self.scope
            && (sensor != &capsule.sensor_id || stream != &capsule.stream_id)
        {
            return Err(FrameWindowError::SourceMismatch);
        }
        let capture = capsule.capture;
        let included = if capture.latest < self.window.start || capture.earliest >= self.window.end {
            false
        } else if capture.earliest >= self.window.start && capture.latest < self.window.end {
            true
        } else {
            return Err(FrameWindowError::BoundaryUncertain);
        };
        // Fixed-width rows preserve the exact decoder display order, including exclusions.
        self.decisions.update(&output_index.to_be_bytes());
        self.decisions.update(&segment_index.to_be_bytes());
        self.decisions.update(&expected_capsule_digest.bytes());
        self.decisions.update(&capsule.source_digest.bytes());
        self.decisions.update(&[u8::from(included)]);
        self.seen_segments[offset / 64] |= bit;
        self.observed += 1;
        if self.scope.is_none() {
            self.scope = Some((capsule.sensor_id.clone(), capsule.stream_id.clone()));
        }
        if included {
            self.selected += 1;
            self.selected_capture = Some(match self.selected_capture {
                Some(prior) => CaptureInterval {
                    earliest: prior.earliest.min(capture.earliest),
                    latest: prior.latest.max(capture.latest),
                },
                None => capture,
            });
        }
        Ok(included)
    }

    /// Consume the selector after successful native-range EOF and before output completion.
    ///
    /// `completed_output_frames` is the decoder owner's completed output count, excluding
    /// declared skipped RASL access units. It must match every observed frame. The owner must
    /// not call this on an early loop exit or a failed decode, even if its prefix count matches.
    pub fn finish(
        mut self,
        completed_output_frames: u64,
        cancelled: bool,
    ) -> Result<FrameWindowReceipt, FrameWindowError> {
        if self.failed {
            return Err(FrameWindowError::Fenced);
        }
        if cancelled {
            return Err(FrameWindowError::Cancelled);
        }
        if completed_output_frames != self.observed {
            return Err(FrameWindowError::IncompleteRange);
        }
        let selected_capture = self
            .selected_capture
            .ok_or(FrameWindowError::EmptySelection)?;
        let skipped = self.observed - self.selected;
        self.decisions.update(&[0xff]);
        self.decisions.update(&self.observed.to_be_bytes());
        self.decisions.update(&self.selected.to_be_bytes());
        self.decisions.update(&skipped.to_be_bytes());
        self.decisions.update(&selected_capture.earliest.0.to_be_bytes());
        self.decisions.update(&selected_capture.latest.0.to_be_bytes());
        let selection_digest = ContentDigest::new(
            DigestAlgorithm::Sha256,
            self.decisions.finalize().map_err(|_| FrameWindowError::Limit)?,
        );
        Ok(FrameWindowReceipt {
            request_digest: self.request_digest,
            selection_digest,
            observed_frames: self.observed,
            selected_frames: self.selected,
            skipped_frames: skipped,
            selected_capture,
        })
    }
}

fn valid_digest(value: ContentDigest) -> bool {
    value.algorithm() == DigestAlgorithm::Sha256
        && !value.is_laboratory()
        && value.bytes() != [0; 32]
}
