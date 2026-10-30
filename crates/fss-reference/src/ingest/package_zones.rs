#![forbid(unsafe_code)]
//! Source-verified trained-package tracks -> observed image-zone transitions and sampled dwell.
//!
//! This owner never runs inference or treats foreground as a detector substitute. It consumes
//! the sealed v2 package analysis, uses actual one-to-one assigned source boxes, and keeps every
//! missing/tentative/boundary sample in the timeline. Retention is approved cognition, not a
//! canonical event revision, calibrated class assertion, coverage witness or effect grant.

use std::error::Error;
use std::fmt;
use std::path::PathBuf;

use fss_core::{CaptureInterval, ClockBasis, ContentDigest, LedgerAnchor, SensorId};
use fss_object::ObjectManifest;

use super::package_event::{PackageAnalysisReport, PackageTrackingConfig};
use super::privacy_mask::{MaskBinding, current_mask};
use super::recorded_decode::source_capsule;
use super::zone_dwell::{DwellPolicy, MAX_DWELL_NS};
use super::{RetainedFileImport, RetainedReadLimits};
use crate::{ReferenceDeployment, ReplayCx};

mod compute;
mod json;
mod storage;
mod wire;
pub use json::PackageZoneOperation;
#[cfg(test)]
mod tests;

/// Exact immutable spatial and temporal configuration.
pub const PACKAGE_ZONE_CONFIG_DOMAIN: &str = "fss.package_zone_config.v1";
/// Canonical complete report and its JSON projection schema.
pub const PACKAGE_ZONE_REPORT_DOMAIN: &str = "fss.package_zone_report.v1";
/// Principal-, report- and root-bound cognition retention approval.
pub const PACKAGE_ZONE_APPROVAL_DOMAIN: &str = "fss.package_zone_retention_approval.v1";
/// Current cognition object family; deletion withdraws the selected report.
pub const PACKAGE_ZONE_FAMILY: &str = "package_zone_report";
/// Complete zone-set ceiling; excess zones are never selected by rank.
pub const MAX_PACKAGE_ZONES: usize = 16;
/// Aggregate track × zone × source-frame ceiling, checked before processing any cells.
pub const MAX_PACKAGE_ZONE_CELLS: usize = 8192;
/// Complete transition and dwell-event ceiling.
pub const MAX_PACKAGE_ZONE_EVENTS: usize = 16384;
/// Complete canonical record ceiling.
pub const MAX_PACKAGE_ZONE_REPORT_BYTES: usize = 8 * 1024 * 1024;
/// Complete JSON delivery ceiling, including safety statements and retention receipt.
pub const MAX_PACKAGE_ZONE_JSON_BYTES: usize = 16 * 1024 * 1024;
/// Cancellation boundary after durable root publication, before cognition authority.
pub const STAGE_PACKAGE_ZONES_COMMIT: &str = "package_zones:commit";

/// Refusals produce no partial successful derivation or invented negative observation.
#[derive(Debug)]
pub enum PackageZoneError {
    /// Invalid configuration, capture-time admission or unsupported coordinate basis.
    Invalid(&'static str),
    /// Complete input, aggregate work or output bound.
    Limit,
    /// Source custody, canonical bytes or exact replay disagrees.
    Mismatch,
    /// Selected report is not currently retained, or an exact proof was withdrawn.
    Unavailable,
    /// Approval belongs to another principal, configuration, report or publication root.
    StaleApproval,
    /// Prepared result was carried to another deployment or principal.
    AuthorityChanged,
    /// Cooperative cancellation; a durable unpublished root may remain.
    Cancelled,
    /// Existing source, privacy, storage, tracking or publication owner refused.
    Source(Box<dyn Error>),
}
impl fmt::Display for PackageZoneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "package zones invalid: {reason}"),
            Self::Limit => f.write_str("package zones complete work/output bound exceeded"),
            Self::Mismatch => f.write_str("package zones source or exact replay mismatch"),
            Self::Unavailable => f.write_str("package zones retained proof unavailable"),
            Self::StaleApproval => f.write_str("package zones retention approval changed"),
            Self::AuthorityChanged => f.write_str("package zones deployment or principal changed"),
            Self::Cancelled => f.write_str("package zones cancelled"),
            Self::Source(error) => write!(f, "package zones owner refused: {error}"),
        }
    }
}
impl Error for PackageZoneError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Source(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}
/// A complete native result or typed refusal.
pub type Result<T> = std::result::Result<T, PackageZoneError>;
fn source<E: Error + 'static>(error: E) -> PackageZoneError {
    PackageZoneError::Source(Box::new(error))
}
fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<()> {
    cx.checkpoint(stage)
        .map_err(|_| PackageZoneError::Cancelled)
}

/// One owner-selected image rectangle, in source pixels, not a physical property boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageZone {
    /// Stable local identifier, 1..64 ASCII alphanumerics, hyphen or underscore.
    pub id: String,
    /// Left source-pixel edge.
    pub x: u32,
    /// Top source-pixel edge.
    pub y: u32,
    /// Positive source-pixel width.
    pub width: u32,
    /// Positive source-pixel height.
    pub height: u32,
    /// Expand assigned boxes by this many pixels before definite side classification.
    pub margin: u32,
}
/// Optional sampled-duration threshold; never continuous-presence evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageZoneDwell {
    /// Required lower endpoint-separation bound in nanoseconds.
    pub minimum_duration_ns: u64,
    /// Actual confirmed inside sightings, including both endpoints.
    pub minimum_observations: usize,
}
/// Complete immutable operator assumptions; a changed value produces another report identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageZoneConfig {
    /// Maximum possible gap between adjacent actual sightings, in nanoseconds.
    pub maximum_sample_gap_ns: u64,
    /// Optional sampled dwell rule.
    pub dwell: Option<PackageZoneDwell>,
    /// Complete zone set; canonical order is ascending ID.
    pub zones: Vec<PackageZone>,
}
impl PackageZoneConfig {
    fn normalized(mut self, dimensions: [u32; 2]) -> Result<Self> {
        if self.zones.is_empty() || self.zones.len() > MAX_PACKAGE_ZONES {
            return Err(PackageZoneError::Limit);
        }
        if !(1..=MAX_DWELL_NS).contains(&self.maximum_sample_gap_ns) {
            return Err(PackageZoneError::Invalid("invalid maximum sample gap"));
        }
        if let Some(policy) = self.dwell_policy() {
            policy.validate().map_err(source)?;
        }
        self.zones.sort_by(|a, b| a.id.cmp(&b.id));
        for (index, zone) in self.zones.iter().enumerate() {
            if zone.id.is_empty()
                || zone.id.len() > 64
                || !zone
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                || (index > 0 && self.zones[index - 1].id == zone.id)
                || zone.width == 0
                || zone.height == 0
                || zone.margin > 65536
                || zone
                    .x
                    .checked_add(zone.width)
                    .is_none_or(|x| x > dimensions[0])
                || zone
                    .y
                    .checked_add(zone.height)
                    .is_none_or(|y| y > dimensions[1])
            {
                return Err(PackageZoneError::Invalid(
                    "invalid, duplicate or out-of-grid image zone",
                ));
            }
        }
        Ok(self)
    }
    fn dwell_policy(&self) -> Option<DwellPolicy> {
        self.dwell.map(|dwell| DwellPolicy {
            minimum_duration_ns: dwell.minimum_duration_ns,
            maximum_sample_gap_ns: self.maximum_sample_gap_ns,
            minimum_observations: dwell.minimum_observations,
        })
    }
}

/// Relation of the expanded complete assigned box, or an explicit unavailable measurement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackageZoneRelation {
    /// Whole expanded assigned box is strictly inside the rectangle.
    Inside,
    /// Expanded box is strictly separated from the rectangle.
    Outside,
    /// Touching, intersecting or within the chosen margin.
    Boundary,
    /// Detector clipped the silhouette; definite membership is unavailable.
    Partial,
    /// No actual assignment on this source frame, including coasting and retirement.
    Unobserved,
    /// Owner privacy mask overlaps this zone; membership is unavailable.
    Masked,
}
impl PackageZoneRelation {
    /// Stable JSON spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inside => "inside",
            Self::Outside => "outside",
            Self::Boundary => "boundary",
            Self::Partial => "partial",
            Self::Unobserved => "unobserved",
            Self::Masked => "masked",
        }
    }
}
/// Source position in the complete retained detector range, in its display order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageZoneFrame {
    /// Retained segment coordinate.
    pub segment: u64,
    /// Exact original source capsule.
    pub capsule_digest: ContentDigest,
    /// Original conservative capture bounds; never receive time.
    pub capture: CaptureInterval,
    /// Exact source image grid.
    pub dimensions: [u32; 2],
    /// Explicit source assumptions and omissions permit elapsed-time arithmetic.
    pub time_reliable: bool,
    /// Source discontinuity before this position.
    pub source_boundary: bool,
}
/// One cell of the complete track × zone × source-frame timeline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageZoneCell {
    /// Exact anonymous package track identity, not physical identity.
    pub track: ContentDigest,
    /// Zone index in the normalized complete configuration.
    pub zone: usize,
    /// Frame index in the complete report.
    pub frame: usize,
    /// Explicit geometry or unavailable observation.
    pub relation: PackageZoneRelation,
    /// Confirmation at this actual sample, excluding earlier tentative samples.
    pub sample_confirmed: bool,
    /// Actual one-to-one assigned detector row, if any.
    pub detection_row: Option<u64>,
    /// Actual source-grid XYXY bounds in 1/256 pixels, never predicted track coordinates.
    pub bounds: Option<[u32; 4]>,
    /// Whether the assigned detector box was clipped.
    pub clipped: bool,
}
/// Derived observation kinds without severity, calibration or effect authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum PackageZoneEventKind {
    /// First confirmed inside sighting after startup or interruption.
    ObservedInside,
    /// Consecutive usable outside and inside sightings on the same anonymous trajectory.
    EnteredBetweenObservations,
    /// Consecutive usable inside and outside sightings; never track disappearance.
    LeftBetweenObservations,
    /// Usable observation continuity was lost; this is not departure or absence.
    ObservationInterrupted,
    /// Maximal qualifying run of actual confirmed inside sightings.
    SampledDwell,
}
impl PackageZoneEventKind {
    /// Stable JSON spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObservedInside => "observed_inside",
            Self::EnteredBetweenObservations => "entered_between_observations",
            Self::LeftBetweenObservations => "left_between_observations",
            Self::ObservationInterrupted => "observation_interrupted",
            Self::SampledDwell => "sampled_dwell",
        }
    }
}
/// Exact endpoints of one derived observation; its stable address is (report digest, index).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageZoneEvent {
    /// Derived observation class.
    pub kind: PackageZoneEventKind,
    /// Exact anonymous package trajectory.
    pub track: ContentDigest,
    /// Zone index in the complete normalized configuration.
    pub zone: usize,
    /// Earlier actual source endpoint, when one exists.
    pub from_frame: Option<usize>,
    /// Triggering source frame, including explicit interruption inputs.
    pub at_frame: usize,
    /// Last actual inside sighting of a dwell run; otherwise the triggering frame.
    pub through_frame: usize,
    /// Actual inside sightings for dwell; zero for interruption, one/two for transitions.
    pub observations: usize,
    /// Conservative full-run lower endpoint separation; only populated for dwell.
    pub minimum_duration_ns: Option<u128>,
    /// Conservative full-run upper endpoint separation; only populated for dwell.
    pub maximum_duration_ns: Option<u128>,
}

/// Sealed native derivation and its exact source-closed retention proposal.
#[derive(Debug)]
pub struct PackageZoneReport {
    site: String,
    root: PathBuf,
    principal: String,
    analysis: PackageAnalysisReport,
    config: PackageZoneConfig,
    capture_time_label: String,
    clock: ClockBasis,
    privacy: MaskBinding,
    frames: Vec<PackageZoneFrame>,
    cells: Vec<PackageZoneCell>,
    events: Vec<PackageZoneEvent>,
    bytes: Vec<u8>,
    digest: ContentDigest,
    manifest: ObjectManifest,
    approval: ContentDigest,
    retention: Option<LedgerAnchor>,
}
impl PackageZoneReport {
    /// Reopen one exact retained class-selected package analysis, then derive complete zones.
    /// The source owner reads original retained bytes once per admitted analysis, never once
    /// per track/zone. No neural execution, foreground detection or loose-file input is used.
    pub fn analyze(
        deployment: &ReferenceDeployment,
        package_report: ContentDigest,
        label: &str,
        tracking: PackageTrackingConfig,
        config: PackageZoneConfig,
        cx: &ReplayCx,
    ) -> Result<Self> {
        checkpoint(cx, "package_zones:analyze")?;
        storage::check_scope(deployment, cx)?;
        storage::check_history_bound(deployment)?;
        let analysis = PackageAnalysisReport::read(deployment, package_report, label, tracking, cx)
            .map_err(source)?;
        storage::check_detection(deployment, &analysis)?;
        let record = analysis.retained().record();
        let first = record.frames.first().ok_or(PackageZoneError::Mismatch)?;
        let config = config.normalized(first.dimensions)?;
        compute::admit(
            analysis.tracks().len(),
            record.frames.len(),
            config.zones.len(),
        )?;
        if record
            .frames
            .iter()
            .any(|frame| frame.dimensions != first.dimensions)
        {
            return Err(PackageZoneError::Invalid(
                "image-zone coordinate grid changed",
            ));
        }
        let retained = RetainedFileImport::open(
            deployment,
            record.import_identity,
            RetainedReadLimits::default(),
            cx,
        )
        .map_err(source)?;
        let capture_time_label = retained.manifest().capture_time_label.clone();
        if config.dwell.is_some() && capture_time_label != "operator_assumption" {
            return Err(PackageZoneError::Invalid(
                "sampled dwell requires explicit capture-time hints",
            ));
        }
        let segment = usize::try_from(first.segment).map_err(|_| PackageZoneError::Limit)?;
        let (capsule, _) = source_capsule(deployment, &retained, segment).map_err(source)?;
        let clock = capsule.clock_basis;
        let sensor = SensorId::parse(&first.sensor_id).map_err(source)?;
        let privacy = current_mask(deployment, &sensor).map_err(source)?;
        let omitted = retained
            .manifest()
            .omission_spans
            .iter()
            .any(|span| span.len > 0 && !span.is_container_structure());
        let first_gap = retained
            .manifest()
            .segment_spans
            .iter()
            .find(|span| span.segment_index > 0 && span.gap_before)
            .map(|span| span.segment_index as u64);
        let frames = record
            .frames
            .iter()
            .map(|frame| PackageZoneFrame {
                segment: frame.segment,
                capsule_digest: frame.capsule_digest,
                capture: frame.capture,
                dimensions: frame.dimensions,
                time_reliable: capture_time_label == "operator_assumption"
                    && !omitted
                    && first_gap.is_none_or(|gap| frame.segment < gap),
                source_boundary: analysis
                    .boundaries()
                    .iter()
                    .any(|b| b.before_segment == frame.segment),
            })
            .collect::<Vec<_>>();
        let (cells, events) = compute::derive(&analysis, &config, &frames, &privacy, cx)?;
        let bytes = wire::encode(
            deployment.site_lineage(),
            &analysis,
            &config,
            &capture_time_label,
            clock,
            &privacy,
            &frames,
            &cells,
            &events,
        )?;
        let digest = ContentDigest::sha256(&bytes);
        let manifest = storage::manifest(&analysis, digest, &config, &privacy)?;
        let principal = cx.io_authority().principal().to_owned();
        let approval = storage::approval(&principal, digest, manifest.root());
        let mut report = Self {
            site: deployment.site_lineage().to_owned(),
            root: deployment.root().to_path_buf(),
            principal,
            analysis,
            config,
            capture_time_label,
            clock,
            privacy,
            frames,
            cells,
            events,
            bytes,
            digest,
            manifest,
            approval,
            retention: None,
        };
        report.retention = storage::existing(deployment, &report)?;
        checkpoint(cx, "package_zones:complete")?;
        Ok(report)
    }
    /// Exact canonical bytes, preserving the underlying v2 package-analysis format.
    pub fn encoded(&self) -> &[u8] {
        &self.bytes
    }
    /// Complete report identity; no summary or ranked subset is hashed in its place.
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }
    /// Exact source-closed publication root prepared for cognition retention.
    pub fn provenance_root(&self) -> ContentDigest {
        self.manifest.root()
    }
    /// Principal-bound retention approval, distinct from canonical event approval.
    pub fn approval_digest(&self) -> ContentDigest {
        self.approval
    }
    /// Exact retained native analysis with its package/class/source bindings.
    pub fn analysis(&self) -> &PackageAnalysisReport {
        &self.analysis
    }
    /// Complete normalized configuration.
    pub fn config(&self) -> &PackageZoneConfig {
        &self.config
    }
    /// Complete source-frame sequence.
    pub fn frames(&self) -> &[PackageZoneFrame] {
        &self.frames
    }
    /// Complete track × zone × frame matrix.
    pub fn cells(&self) -> &[PackageZoneCell] {
        &self.cells
    }
    /// Every derived transition and qualifying maximal dwell run.
    pub fn events(&self) -> &[PackageZoneEvent] {
        &self.events
    }
    /// Original cognition commit anchor, if already retained and fully verified.
    pub fn retention_anchor(&self) -> Option<&LedgerAnchor> {
        self.retention.as_ref()
    }
}
