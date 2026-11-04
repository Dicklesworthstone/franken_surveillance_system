#![forbid(unsafe_code)]
//! Typed observation vocabulary. Zone roles are operator annotations, never detected semantics.

use std::collections::BTreeSet;

use fss_core::ContentDigest;

use super::{QsrError, Result};
use crate::ingest::package_zones::PackageZoneEvent;

/// Maximum complete role and lane-stage lists, matching the existing source-zone owner.
pub const MAX_QSR_ZONES: usize = 16;

/// Operator-declared purpose of an image region; does not assert an object is being served.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QsrZoneRole {
    /// General sampled zone observation.
    Area,
    /// Owner-named queue region; counts remain sampled observed tracks.
    Queue,
    /// Owner-named register region; presence carries no transaction or person identity.
    Register,
    /// One named region in the explicit ordered lane-stage list.
    LaneStage,
}
impl QsrZoneRole {
    /// Stable registered spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Area => "area",
            Self::Queue => "queue",
            Self::Register => "register",
            Self::LaneStage => "lane_stage",
        }
    }
}
/// One role annotation for an exact existing source-zone ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QsrZoneBinding {
    /// Existing zone ID, never a new or changed polygon.
    pub zone: String,
    /// Explicit owner annotation.
    pub role: QsrZoneRole,
}
/// Bounded read configuration. Unannotated source zones default to `area`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct QsrConfig {
    /// Unique existing source zones; canonical report order is ascending zone ID.
    pub zone_roles: Vec<QsrZoneBinding>,
    /// Zero, or two through sixteen distinct existing zones, in intended travel order.
    pub lane_stages: Vec<String>,
}
fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}
impl QsrConfig {
    pub(super) fn validate_shape(&self) -> Result<()> {
        if self.zone_roles.len() > MAX_QSR_ZONES || self.lane_stages.len() > MAX_QSR_ZONES {
            return Err(QsrError::Limit);
        }
        if self.lane_stages.len() == 1 {
            return Err(QsrError::Invalid("a lane requires at least two stages"));
        }
        let mut roles = BTreeSet::new();
        for binding in &self.zone_roles {
            if !valid_id(&binding.zone) || !roles.insert(&binding.zone) {
                return Err(QsrError::Invalid("invalid or duplicate zone role"));
            }
        }
        let mut stages = BTreeSet::new();
        for stage in &self.lane_stages {
            if !valid_id(stage) || !stages.insert(stage) {
                return Err(QsrError::Invalid("invalid or duplicate lane stage"));
            }
        }
        Ok(())
    }
    pub(super) fn normalized(&self, zones: &[String]) -> Result<Self> {
        self.validate_shape()?;
        if zones.is_empty()
            || zones.len() > MAX_QSR_ZONES
            || zones.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(QsrError::Mismatch);
        }
        if self
            .zone_roles
            .iter()
            .any(|binding| !zones.contains(&binding.zone))
            || self.lane_stages.iter().any(|stage| !zones.contains(stage))
        {
            return Err(QsrError::Invalid("annotation names an unknown source zone"));
        }
        let mut zone_roles = Vec::new();
        for zone in zones {
            let requested = self
                .zone_roles
                .iter()
                .find(|binding| binding.zone == *zone)
                .map(|binding| binding.role);
            let in_lane = self.lane_stages.contains(zone);
            if requested.is_some_and(|role| (role == QsrZoneRole::LaneStage) != in_lane) {
                return Err(QsrError::Invalid(
                    "lane-stage role conflicts with ordered lane",
                ));
            }
            zone_roles.push(QsrZoneBinding {
                zone: zone.clone(),
                role: requested.unwrap_or(if in_lane {
                    QsrZoneRole::LaneStage
                } else {
                    QsrZoneRole::Area
                }),
            });
        }
        Ok(Self {
            zone_roles,
            lane_stages: self.lane_stages.clone(),
        })
    }
}

/// Presence of confirmed assigned boxes in this one sample, never physical absence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QsrPresence {
    /// At least one confirmed complete box lies strictly inside the zone.
    Observed,
    /// No confirmed inside box was observed; detector recall and physical absence are unknown.
    NotObserved,
    /// Historical screening or privacy prevents even a sampled observation count.
    Unknown,
}
impl QsrPresence {
    /// Stable registered spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::NotObserved => "not_observed",
            Self::Unknown => "unknown",
        }
    }
}
/// One complete zone × source-frame observation, preserving withheld evidence separately.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QsrZoneSample {
    /// Zone index in the complete normalized configuration.
    pub zone: usize,
    /// Source-frame index in the verified package-zone report.
    pub frame: usize,
    /// Sampled positive, sampled non-observation or unavailable observation.
    pub presence: QsrPresence,
    /// Actual confirmed inside track identities. Empty when observation support is unavailable.
    pub confirmed_tracks: Vec<ContentDigest>,
    /// Current source mask overlaps the zone, including when there are zero tracks.
    pub masked: bool,
    /// Matching complete finite historical screen without findings, not current camera health.
    pub historical_screen_support: bool,
    /// Actual assigned but not-yet-confirmed tracks, regardless of zone side.
    pub tentative_tracks: usize,
    /// Confirmed boxes touching/intersecting the zone boundary.
    pub boundary_tracks: usize,
    /// Confirmed clipped boxes whose full zone relation is unavailable.
    pub partial_tracks: usize,
    /// Tracks without an actual assignment on this frame; never counted from predictions.
    pub unobserved_tracks: usize,
}
/// Complete sample aggregation for one zone; identities are analysis-local anonymous tracks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QsrZoneSummary {
    /// Zone index in the complete normalized configuration.
    pub zone: usize,
    /// Number of source frames in the selected finite report.
    pub sampled_frames: usize,
    /// Frames with admitted sampled counts, including counts of zero.
    pub supported_frames: usize,
    /// Frames with no admitted sampled count.
    pub unknown_frames: usize,
    /// Supported frames with at least one confirmed inside observation.
    pub frames_with_observed_tracks: usize,
    /// Maximum actual observed track count; unknown when no sample was admitted.
    pub maximum_observed_count: Option<usize>,
    /// Unique observed track IDs, never a count of unique physical people or vehicles.
    pub observed_tracks: Vec<ContentDigest>,
}
/// Why an in-progress observed lane sequence could not be continued.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QsrLaneInterruptionReason {
    /// Explicit source-continuity boundary.
    SourceBoundary,
    /// Historical screening unavailable, incomplete or finding-bearing.
    HistoricalScreening,
    /// A named lane stage is privacy-masked.
    MaskedStage,
    /// A source sample has no admitted capture-time interpretation.
    UnreliableTime,
    /// No complete confirmed actual track assignment.
    MissingObservation,
    /// Maximum possible gap between adjacent source samples exceeded the policy.
    SampleGap,
    /// A complete box belongs to more than one lane stage at once.
    AmbiguousStage,
    /// Next observed stage was beyond the adjacent declared stage.
    SkippedStage,
    /// Next observed stage went backward through the declared lane order.
    ReversedStage,
}
impl QsrLaneInterruptionReason {
    /// Stable machine spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceBoundary => "source_boundary",
            Self::HistoricalScreening => "historical_screening",
            Self::MaskedStage => "masked_stage",
            Self::UnreliableTime => "unreliable_time",
            Self::MissingObservation => "missing_observation",
            Self::SampleGap => "sample_gap",
            Self::AmbiguousStage => "ambiguous_stage",
            Self::SkippedStage => "skipped_stage",
            Self::ReversedStage => "reversed_stage",
        }
    }
}
/// Adjacent ordered-stage endpoint observation on one uninterrupted anonymous trajectory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QsrLaneTransition {
    /// Exact model-track identity within the retained analysis.
    pub track: ContentDigest,
    /// Earlier index in `lane_stages`.
    pub from_stage: usize,
    /// Next adjacent index in `lane_stages`.
    pub to_stage: usize,
    /// First admitted inside sample of the earlier stage.
    pub from_frame: usize,
    /// First admitted inside sample of the next stage.
    pub at_frame: usize,
    /// Conservative lower endpoint-separation bound, not a service-duration estimate.
    pub minimum_elapsed_ns: u128,
    /// Conservative upper endpoint-separation bound.
    pub maximum_elapsed_ns: u128,
}
/// Explicit break of a previously observed lane-stage sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QsrLaneInterruption {
    /// Exact anonymous model-track identity.
    pub track: ContentDigest,
    /// Stage whose sequence was interrupted.
    pub from_stage: usize,
    /// First admitted inside sample of that stage.
    pub from_frame: usize,
    /// Source frame causing interruption.
    pub at_frame: usize,
    /// Typed uncertainty or ordering reason.
    pub reason: QsrLaneInterruptionReason,
}
/// Complete derived observations. Dwell retains the original source owner's exact endpoints.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QsrObservations {
    /// All zone summaries, in source-zone order.
    pub zones: Vec<QsrZoneSummary>,
    /// All zone × source-frame cells, in zone then frame order.
    pub samples: Vec<QsrZoneSample>,
    /// Original sampled-dwell events, never converted into continuous occupancy or queue wait.
    pub dwell: Vec<PackageZoneEvent>,
    /// Every adjacent observed lane-stage transition.
    pub lane_transitions: Vec<QsrLaneTransition>,
    /// Every interrupted in-progress lane sequence.
    pub lane_interruptions: Vec<QsrLaneInterruption>,
}
