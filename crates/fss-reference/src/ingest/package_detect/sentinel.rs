#![forbid(unsafe_code)]
//! Motion-independent sentinel bursts (FSS-078, RISK-007, OPEN-006).
//!
//! The foreground cascade cannot recover an object that never creates a foreground track.
//! This path chooses short contiguous detector bursts from segment coordinates alone: no motion,
//! detector score, previous event or background estimate can suppress a scheduled burst. One
//! explicit inference allowance covers the entire invocation; only whole bursts are admitted.
//!
//! Each completed burst is an ordinary [`PackageDetectReport`] and can follow the existing
//! retained-package -> label tracking -> exact approved event workflow. Bursts are separate
//! reports, never one sparse sequence misrepresented as continuous tracking. Unsampled time and
//! budget-skipped bursts certify neither absence nor sensor health. No event or effect is
//! automatically published, and no real-world recall, calibration or quality is claimed.
//!
//! MJPEG decodes only admitted frames. AVC/HEVC decode the whole bounded IDR/IRAP-led source
//! range once to preserve codec references, but RGB conversion and inference occur only on
//! admitted segments. Decode and head-work budgets are shared, not restarted per burst.
//! Missing selected pictures, source gaps within a burst, format/decode refusals and cancellation
//! refuse the entire computation: no partial burst is labelled complete.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use fss_core::{CanonicalEncoder, ContentDigest};

use super::{
    MAX_PACKAGE_DETECT_FRAMES, PackageDetectError, PackageDetectFrame, PackageDetectLimits,
    PackageDetectReport, PackageDetectRequest, ReferenceDeployment, ReplayCx, RgbDetectionContract,
    RgbDetectorPackage, ScalarExecCx, finish_report, json_string, run_selected_detection,
};
use crate::ingest::privacy_mask::MaskBinding;

/// Bounded control/report schema; child reports retain their existing canonical contract.
pub const SENTINEL_REPORT_SCHEMA: &str = "fss.sentinel_detection_report.v1";
/// Sampling and inference-admission policy identity.
pub const SENTINEL_POLICY: &str = "fss.sentinel_policy.v1:relative-segment-period:whole-burst-prefix:motion-independent:no-gap-bridging";
/// Maximum consecutive frames of a sentinel burst.
pub const MAX_SENTINEL_BURST_FRAMES: usize = 8;
/// Maximum aggregate rendered report, checked before it can be returned or published.
pub const MAX_SENTINEL_REPORT_BYTES: usize = 16 * 1024 * 1024;

/// Explicit, immutable sampling choices. Resource changes are visible in the schedule digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SentinelConfig {
    /// Distance between burst starts, in source segments, 1..=64.
    pub every_frames: usize,
    /// Consecutive segments in each burst, 1..=8 and no larger than the period.
    pub burst_frames: usize,
    /// Total inference allowance, at least one burst and at most 64 frames.
    pub max_inferences: usize,
}
impl Default for SentinelConfig {
    fn default() -> Self {
        Self {
            every_frames: 16,
            burst_frames: 3,
            max_inferences: 12,
        }
    }
}
impl SentinelConfig {
    /// Validate all bounds before any source read or inference.
    pub fn validate(&self) -> Result<(), PackageDetectError> {
        if self.every_frames == 0
            || self.every_frames > MAX_PACKAGE_DETECT_FRAMES
            || self.burst_frames == 0
            || self.burst_frames > MAX_SENTINEL_BURST_FRAMES
            || self.burst_frames > self.every_frames
            || self.max_inferences < self.burst_frames
            || self.max_inferences > MAX_PACKAGE_DETECT_FRAMES
        {
            return Err(PackageDetectError::InvalidRequest);
        }
        Ok(())
    }
}

/// One full scheduled burst; `admitted` is budget selection, not execution success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SentinelBurst {
    /// First source segment, inclusive.
    pub first_segment: usize,
    /// Consecutive source segments in this burst.
    pub segment_count: usize,
    /// Whether the complete burst fits the remaining invocation allowance.
    pub admitted: bool,
}

/// Validated deterministic schedule. Fields are private so execution cannot inherit a forged set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SentinelPlan {
    first: usize,
    count: usize,
    config: SentinelConfig,
    bursts: Vec<SentinelBurst>,
}
impl SentinelPlan {
    /// Compile the bounded schedule without consulting footage, motion, models or a clock.
    ///
    /// The first burst starts at `first_segment`, then every `every_frames` segments. Only
    /// complete bursts inside the requested range are scheduled. The final short tail is
    /// unsampled, not a shorter burst. At budget exhaustion later full bursts remain explicit.
    pub fn new(
        first_segment: usize,
        segment_count: usize,
        config: SentinelConfig,
    ) -> Result<Self, PackageDetectError> {
        config.validate()?;
        if segment_count < config.burst_frames
            || segment_count > MAX_PACKAGE_DETECT_FRAMES
            || first_segment.checked_add(segment_count).is_none()
            || u64::try_from(first_segment).is_err()
        {
            return Err(PackageDetectError::InvalidRequest);
        }
        let mut bursts = Vec::new();
        let mut remaining = config.max_inferences;
        for offset in (0..segment_count).step_by(config.every_frames) {
            if config.burst_frames > segment_count - offset {
                break;
            }
            let admitted = remaining >= config.burst_frames;
            if admitted {
                remaining -= config.burst_frames;
            }
            bursts.push(SentinelBurst {
                first_segment: first_segment + offset,
                segment_count: config.burst_frames,
                admitted,
            });
        }
        Ok(Self {
            first: first_segment,
            count: segment_count,
            config,
            bursts,
        })
    }

    /// Scheduled full bursts in source order, including every budget refusal.
    #[must_use]
    pub fn bursts(&self) -> &[SentinelBurst] {
        &self.bursts
    }

    /// Exact source identities admitted for inference, never more than `max_inferences`.
    #[must_use]
    pub fn selected_segments(&self) -> BTreeSet<usize> {
        self.bursts
            .iter()
            .filter(|burst| burst.admitted)
            .flat_map(|burst| burst.first_segment..burst.first_segment + burst.segment_count)
            .collect()
    }

    /// Every requested segment not admitted to inference, in source order.
    #[must_use]
    pub fn unsampled_segments(&self) -> Vec<usize> {
        let selected = self.selected_segments();
        (self.first..self.first + self.count)
            .filter(|s| !selected.contains(s))
            .collect()
    }

    /// Policy/range/allowance identity. The enclosing result separately binds source and model.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text(SENTINEL_POLICY);
        for value in [
            self.first,
            self.count,
            self.config.every_frames,
            self.config.burst_frames,
            self.config.max_inferences,
        ] {
            e.u64(value as u64);
        }
        ContentDigest::sha256(&e.finish())
    }
}

/// Completed computation, with independent contiguous child reports for existing event APIs.
#[derive(Debug)]
pub struct SentinelReport {
    plan: SentinelPlan,
    reports: Vec<PackageDetectReport>,
    json: String,
    digest: ContentDigest,
}
impl SentinelReport {
    /// Exact sampling schedule and explicit budget-skipped bursts.
    #[must_use]
    pub fn plan(&self) -> &SentinelPlan {
        &self.plan
    }
    /// Completed contiguous reports. Track each separately; do not concatenate their frames.
    #[must_use]
    pub fn reports(&self) -> &[PackageDetectReport] {
        &self.reports
    }
    /// Complete bounded JSON. This is a report, not an event or publication acknowledgement.
    #[must_use]
    pub fn json(&self) -> &str {
        &self.json
    }
    /// SHA-256 of the complete JSON bytes, including schedule, omissions and child identities.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }
}

/// Run motion-independent sentinel detection through the same verified native package path.
///
/// `request` describes the whole source/decode range, not a list of independent video seeks.
/// The source must meet the existing MJPEG/AVC/HEVC admission contract. One `FrameRun`, JPEG
/// work counter and native video decoder serve all bursts; budgets do not reset at a boundary.
/// Every child report contains a full burst and is consumable by `retain_package_detection`.
/// Decode or cancellation failure yields no report and this function performs no writes.
#[allow(clippy::too_many_arguments)]
pub fn run_sentinel_detection(
    deployment: &ReferenceDeployment,
    package: &RgbDetectorPackage,
    request: &PackageDetectRequest,
    config: SentinelConfig,
    limits: &PackageDetectLimits,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
) -> Result<SentinelReport, PackageDetectError> {
    cx.checkpoint("sentinel_detect:begin")
        .map_err(|_| PackageDetectError::Cancelled)?;
    let plan = SentinelPlan::new(request.first_segment, request.segment_count, config)?;
    let selected = plan.selected_segments();
    run_selected_detection(
        deployment,
        package,
        request,
        limits,
        cx,
        scalar,
        Some(&selected),
        |contract, import_root, media_format, frames, privacy| {
            build_report(
                package,
                request,
                contract,
                import_root,
                media_format,
                privacy,
                frames,
                plan,
            )
        },
    )
}

fn invalid_burst(segment: usize, reason: &'static str) -> PackageDetectError {
    PackageDetectError::Frame {
        segment,
        source: reason.into(),
    }
}

fn validate_burst(
    burst: SentinelBurst,
    frames: &[PackageDetectFrame],
) -> Result<(), PackageDetectError> {
    let first = frames
        .first()
        .ok_or_else(|| invalid_burst(burst.first_segment, "empty sentinel burst"))?;
    if frames.len() != burst.segment_count {
        return Err(invalid_burst(
            burst.first_segment,
            "incomplete sentinel burst",
        ));
    }
    let mut seen = BTreeSet::new();
    for frame in frames {
        if frame.segment < burst.first_segment
            || frame.segment >= burst.first_segment + burst.segment_count
            || !seen.insert(frame.segment)
            || frame.capsule.sensor_id != first.capsule.sensor_id
            || frame.capsule.clock_basis != first.capsule.clock_basis
            || frame.dimensions != first.dimensions
        {
            return Err(invalid_burst(
                frame.segment,
                "sentinel burst identities, clock or dimensions disagree",
            ));
        }
        if frame.segment != burst.first_segment && frame.capsule.gap_before {
            return Err(invalid_burst(
                frame.segment,
                "source gap inside a sentinel burst",
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_report(
    package: &RgbDetectorPackage,
    request: &PackageDetectRequest,
    contract: &RgbDetectionContract,
    import_root: ContentDigest,
    media_format: String,
    privacy: MaskBinding,
    frames: Vec<PackageDetectFrame>,
    plan: SentinelPlan,
) -> Result<SentinelReport, PackageDetectError> {
    let mut groups: Vec<Vec<PackageDetectFrame>> =
        (0..plan.bursts.len()).map(|_| Vec::new()).collect();
    for frame in frames {
        let index = plan
            .bursts
            .iter()
            .position(|burst| {
                burst.admitted
                    && frame.segment >= burst.first_segment
                    && frame.segment < burst.first_segment + burst.segment_count
            })
            .ok_or(PackageDetectError::InvalidRequest)?;
        // Preserve the native decoder's display order inside each independent burst.
        groups[index].push(frame);
    }
    let mut reports = Vec::new();
    let mut json_bytes = 0_usize;
    for (burst, frames) in plan.bursts.iter().copied().zip(groups) {
        if !burst.admitted {
            continue;
        }
        validate_burst(burst, &frames)?;
        let burst_request = PackageDetectRequest {
            first_segment: burst.first_segment,
            segment_count: burst.segment_count,
            ..request.clone()
        };
        let report = finish_report(
            package,
            &burst_request,
            contract,
            import_root,
            media_format.clone(),
            frames,
            privacy.clone(),
        )?;
        json_bytes = json_bytes
            .checked_add(report.json.len())
            .ok_or(PackageDetectError::InvalidRequest)?;
        if json_bytes > MAX_SENTINEL_REPORT_BYTES {
            return Err(PackageDetectError::InvalidRequest);
        }
        reports.push(report);
    }
    let json = render_report(
        package,
        request,
        import_root,
        &media_format,
        &privacy,
        &plan,
        &reports,
    )
    .map_err(|_| PackageDetectError::InvalidRequest)?;
    if json.len() > MAX_SENTINEL_REPORT_BYTES {
        return Err(PackageDetectError::InvalidRequest);
    }
    let digest = ContentDigest::sha256(json.as_bytes());
    Ok(SentinelReport {
        plan,
        reports,
        json,
        digest,
    })
}

#[allow(clippy::too_many_arguments)]
fn render_report(
    package: &RgbDetectorPackage,
    request: &PackageDetectRequest,
    import_root: ContentDigest,
    media_format: &str,
    privacy: &MaskBinding,
    plan: &SentinelPlan,
    reports: &[PackageDetectReport],
) -> Result<String, std::fmt::Error> {
    let mut out = String::new();
    write!(
        out,
        "{{\"schema\":\"{SENTINEL_REPORT_SCHEMA}\",\"source_import\":\"{}\",\"import_root\":\"{}\",\"package_digest\":\"{}\",\"model_digest\":\"{}\",\"media_format\":{},\"privacy_mask\":{},\"decode_range\":{{\"first_segment\":{},\"segment_count\":{}}},\"sampling\":{{\"policy\":{},\"schedule_digest\":\"{}\",\"every_frames\":{},\"burst_frames\":{},\"max_inferences\":{},\"admitted_inferences\":{},\"motion_independent\":true,\"phase\":\"relative_to_first_segment\"}},\"unsampled_segments\":[",
        request.import_identity,
        import_root,
        package.archive_digest(),
        package.model().digest(),
        json_string(media_format),
        privacy.to_json(),
        plan.first,
        plan.count,
        json_string(SENTINEL_POLICY),
        plan.digest(),
        plan.config.every_frames,
        plan.config.burst_frames,
        plan.config.max_inferences,
        plan.selected_segments().len()
    )?;
    for (index, segment) in plan.unsampled_segments().iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        write!(out, "{segment}")?;
    }
    out.push_str("],\"bursts\":[");
    let mut reports_iter = reports.iter();
    for (index, burst) in plan.bursts.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        write!(
            out,
            "{{\"first_segment\":{},\"segment_count\":{},",
            burst.first_segment, burst.segment_count
        )?;
        if burst.admitted {
            let report = reports_iter.next().ok_or(std::fmt::Error)?;
            write!(
                out,
                "\"status\":\"completed\",\"report_digest\":\"{}\",\"report\":{}}}",
                report.digest,
                report.json.trim_end()
            )?;
        } else {
            out.push_str("\"status\":\"budget_exhausted\",\"report_digest\":null,\"report\":null}");
        }
    }
    let executed: usize = reports.iter().map(|r| r.frames.len()).sum();
    let macs: u128 = reports
        .iter()
        .flat_map(|r| &r.frames)
        .map(|f| u128::from(f.inference.executed_macs()))
        .sum();
    let complete = plan.bursts.iter().all(|b| b.admitted);
    write!(
        out,
        "],\"executed_inferences\":{executed},\"executed_macs\":\"{macs}\",\"scheduled_bursts_complete\":{complete},\"continuous_coverage\":false,\"tracking_across_bursts\":false,\"absence_certifiable\":false,\"effects_authorized\":false,\"model_outputs\":\"uncalibrated\",\"quality_claim\":\"none\",\"retention\":\"not_asserted_by_computation\"}}\n"
    )?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::super::FrameAdmission;
    use super::*;

    #[test]
    fn samples_quiet_intervals_without_a_motion_or_track_input() -> Result<(), PackageDetectError> {
        let plan = SentinelPlan::new(
            10,
            20,
            SentinelConfig {
                every_frames: 8,
                burst_frames: 3,
                max_inferences: 6,
            },
        )?;
        assert_eq!(
            plan.selected_segments(),
            BTreeSet::from([10, 11, 12, 18, 19, 20])
        );
        assert_eq!(plan.bursts().len(), 3);
        assert!(!plan.bursts()[2].admitted);
        assert_eq!(plan.bursts()[2].first_segment, 26);
        assert_eq!(plan.unsampled_segments().len(), 14);
        Ok(())
    }

    #[test]
    fn never_partially_admits_or_shortens_a_burst() -> Result<(), PackageDetectError> {
        let plan = SentinelPlan::new(
            0,
            10,
            SentinelConfig {
                every_frames: 4,
                burst_frames: 3,
                max_inferences: 5,
            },
        )?;
        assert_eq!(plan.selected_segments(), BTreeSet::from([0, 1, 2]));
        assert_eq!(plan.bursts().len(), 2); // The two-frame tail is not a fabricated full burst.
        assert_eq!(plan.bursts()[1].segment_count, 3);
        assert!(!plan.bursts()[1].admitted);
        Ok(())
    }

    #[test]
    fn exhaustive_schedule_matches_independent_membership_oracle() -> Result<(), PackageDetectError>
    {
        for count in 1..=64 {
            for every in 1..=16 {
                for burst in 1..=8.min(every).min(count) {
                    for budget in burst..=64 {
                        let config = SentinelConfig {
                            every_frames: every,
                            burst_frames: burst,
                            max_inferences: budget,
                        };
                        let plan = SentinelPlan::new(37, count, config)?;
                        let expected: BTreeSet<usize> = (0..count)
                            .filter(|offset| {
                                let group = offset / every;
                                offset % every < burst
                                    && group * every + burst <= count
                                    && (group + 1) * burst <= budget
                            })
                            .map(|offset| 37 + offset)
                            .collect();
                        assert_eq!(plan.selected_segments(), expected);
                        assert!(expected.len() <= budget);
                        let unsampled: BTreeSet<_> =
                            plan.unsampled_segments().into_iter().collect();
                        assert!(expected.is_disjoint(&unsampled));
                        assert_eq!(
                            expected.union(&unsampled).copied().collect::<Vec<_>>(),
                            (37..37 + count).collect::<Vec<_>>()
                        );
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn range_and_budget_are_bound_even_when_selected_frames_are_equal()
    -> Result<(), PackageDetectError> {
        let config = SentinelConfig {
            every_frames: 8,
            burst_frames: 3,
            max_inferences: 3,
        };
        let a = SentinelPlan::new(0, 8, config)?;
        let b = SentinelPlan::new(0, 9, config)?;
        let c = SentinelPlan::new(
            0,
            8,
            SentinelConfig {
                max_inferences: 4,
                ..config
            },
        )?;
        assert_eq!(a.selected_segments(), b.selected_segments());
        assert_eq!(a.selected_segments(), c.selected_segments());
        assert_ne!(a.digest(), b.digest());
        assert_ne!(a.digest(), c.digest());
        assert_eq!(a.digest(), SentinelPlan::new(0, 8, config)?.digest());
        Ok(())
    }

    #[test]
    fn rejects_zero_overflow_and_unbounded_configuration() {
        let base = SentinelConfig::default();
        for config in [
            SentinelConfig {
                every_frames: 0,
                ..base
            },
            SentinelConfig {
                every_frames: 65,
                ..base
            },
            SentinelConfig {
                burst_frames: 0,
                ..base
            },
            SentinelConfig {
                burst_frames: 9,
                ..base
            },
            SentinelConfig {
                every_frames: 2,
                ..base
            },
            SentinelConfig {
                max_inferences: 2,
                ..base
            },
            SentinelConfig {
                max_inferences: 65,
                ..base
            },
        ] {
            assert!(SentinelPlan::new(0, 64, config).is_err());
        }
        for (first, count) in [
            (0, 0),
            (0, 2),
            (0, 65),
            (usize::MAX, 3),
            (usize::MAX - 1, 3),
        ] {
            assert!(SentinelPlan::new(first, count, base).is_err());
        }
    }

    #[test]
    fn selected_video_frames_accept_display_order_but_not_duplicates_or_missing_pictures()
    -> Result<(), PackageDetectError> {
        let selection = BTreeSet::from([0, 1, 2]);
        let mut gate = FrameAdmission::new(Some(&selection));
        assert!(gate.admit(0)?);
        assert!(!gate.admit(3)?);
        assert!(gate.admit(2)?);
        assert!(gate.finish().is_err());
        assert!(gate.admit(1)?);
        gate.finish()?;
        assert!(gate.admit(2).is_err());
        // Ordinary detection keeps its existing admission behavior and report bytes.
        let mut ordinary = FrameAdmission::new(None);
        assert!(ordinary.admit(0)?);
        assert!(ordinary.admit(0)?);
        ordinary.finish()?;
        Ok(())
    }
}
