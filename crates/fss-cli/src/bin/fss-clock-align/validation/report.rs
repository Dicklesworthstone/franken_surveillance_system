#![forbid(unsafe_code)]
//! Complete bounded diagnostics; unsupported hypotheses still widen every time hull.

use crate::agent_json::{object, string};
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_geometry::temporal_alignment::drift::validation::ClockValidationReport;
use fss_geometry::temporal_alignment::drift::{ClockDriftScan, ClockRateHypothesis};

use super::super::{MAX_REPORT_BYTES, input};
use super::{Query, Result, checkpoint, drift, failure};

const RESPONSE_SCHEMA: &str = "fss.clock_validation_response.v1";

/// Incremental output allocation. No complete field, trial, session, or warning is truncated.
/// The response wrapper and newline have a fixed reserve outside the report object.
struct Json {
    bytes: String,
    limit: usize,
}

impl Json {
    fn new(limit: usize) -> Self {
        Self {
            bytes: String::new(),
            limit,
        }
    }

    fn raw(&mut self, text: &str, work: &mut WorkBudget<'_>) -> Result<()> {
        checkpoint(work)?;
        if text.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(failure(
                "limit",
                "complete clock validation report exceeds output bound",
            ));
        }
        self.bytes
            .try_reserve(text.len())
            .map_err(|_| failure("limit", "report allocation refused"))?;
        self.bytes.push_str(text);
        Ok(())
    }

    fn name(&mut self, name: &str, work: &mut WorkBudget<'_>) -> Result<()> {
        if !self.bytes.ends_with('{') {
            self.raw(",", work)?;
        }
        self.raw(&string(name), work)?;
        self.raw(":", work)
    }

    fn field(&mut self, name: &str, value: &str, work: &mut WorkBudget<'_>) -> Result<()> {
        self.name(name, work)?;
        self.raw(value, work)
    }

    fn array<T>(
        &mut self,
        rows: impl IntoIterator<Item = T>,
        work: &mut WorkBudget<'_>,
        mut render: impl FnMut(&mut Self, T, &mut WorkBudget<'_>) -> Result<()>,
    ) -> Result<()> {
        self.raw("[", work)?;
        for (index, row) in rows.into_iter().enumerate() {
            if index != 0 {
                self.raw(",", work)?;
            }
            render(self, row, work)?;
        }
        self.raw("]", work)
    }
}

fn times(values: [i128; 2]) -> String {
    format!(
        "[{},{}]",
        string(&values[0].to_string()),
        string(&values[1].to_string())
    )
}

fn source(source: &input::Source) -> String {
    object(&[
        ("camera", string(&source.camera.to_string())),
        ("clock", string(&source.clock.to_string())),
        (
            "role",
            string(if source.validation {
                "validation_constraint"
            } else {
                "nominal_training"
            }),
        ),
        ("original_local_capture_ns", times(source.capture)),
        ("exposure", string(&source.exposure)),
        ("source_digest", string(&source.source.to_text())),
        ("evidence_digest", string(&source.evidence.to_text())),
    ])
}

fn hypothesis(hypothesis: ClockRateHypothesis) -> String {
    object(&[
        ("offset_ns", string(&hypothesis.offset_ns.to_string())),
        ("skew_ppb", string(&hypothesis.skew_ppb.to_string())),
    ])
}

fn scan(
    out: &mut Json,
    id: u64,
    query: &drift::Query,
    scan: &ClockDriftScan,
    work: &mut WorkBudget<'_>,
) -> Result<()> {
    out.raw("{", work)?;
    out.field("session_id", &string(&id.to_string()), work)?;
    out.field(
        "association_evidence",
        &string(&query.common.association.to_text()),
        work,
    )?;
    out.field("work_units", &scan.work_units.to_string(), work)?;
    out.field(
        "all_times_supported_count",
        &scan
            .trials
            .iter()
            .filter(|t| t.consistent_for_all_capture_times())
            .count()
            .to_string(),
        work,
    )?;
    out.name("sources", work)?;
    out.array(&query.common.sources, work, |out, row, work| {
        out.raw(&source(row), work)
    })?;
    out.name("trials", work)?;
    out.array(&scan.trials, work, |out, trial, work| {
        // One trial has at most 128 training and 128 validation rows. It is rendered by the
        // original drift owner; no new diagnostic mapping or successful-prefix shortcut.
        checkpoint(work)?;
        out.raw(&drift::render_trial(trial), work)
    })?;
    out.raw("}", work)
}

pub(super) fn render(
    query: &Query,
    evaluated: &ClockValidationReport,
    digest: ContentDigest,
    work_limit: u64,
    input_bytes: usize,
    work: &mut WorkBudget<'_>,
) -> Result<String> {
    render_bounded(
        query,
        evaluated,
        digest,
        work_limit,
        input_bytes,
        work,
        MAX_REPORT_BYTES,
        false,
    )
}

fn render_bounded(
    query: &Query,
    evaluated: &ClockValidationReport,
    digest: ContentDigest,
    work_limit: u64,
    input_bytes: usize,
    work: &mut WorkBudget<'_>,
    output_limit: usize,
    replay: bool,
) -> Result<String> {
    let response_schema = if replay {
        "fss.clock_validation_replay_response.v1"
    } else {
        RESPONSE_SCHEMA
    };
    let report_schema = if replay {
        "fss.clock_validation_replay_report.v1"
    } else {
        "fss.clock_validation_report.v1"
    };
    // Empty report measures just the wrapper punctuation and constant-sized integrity pin.
    let envelope_size = object(&[
        ("schema", string(response_schema)),
        (
            "report_digest",
            string(&ContentDigest::sha256(b"").to_text()),
        ),
        ("report", String::new()),
    ])
    .len()
        + 1;
    let limit = output_limit.checked_sub(envelope_size).ok_or_else(|| {
        failure(
            "limit",
            "output bound cannot hold the complete response wrapper",
        )
    })?;
    let mut out = Json::new(limit);
    let common = &query.search.common;
    out.raw("{", work)?;
    for (name, value) in [
        ("schema", string(report_schema)),
        ("input_digest", string(&digest.to_text())),
        ("input_bytes", input_bytes.to_string()),
        ("world_basis", string(&common.world.to_text())),
        (
            "reference_camera",
            string(&common.pair.reference_camera.to_string()),
        ),
        (
            "target_camera",
            string(&common.pair.target_camera.to_string()),
        ),
        (
            "reference_clock",
            string(&common.pair.reference_clock.to_string()),
        ),
        (
            "target_clock",
            string(&common.pair.target_clock.to_string()),
        ),
        (
            "target_anchor_ns",
            string(&query.search.target_anchor_ns.to_string()),
        ),
        (
            "mapping",
            string(
                "reference = target_anchor - offset + (target - target_anchor) * 1000000000 / (1000000000 + skew_ppb)",
            ),
        ),
        (
            "training_rounding",
            string(
                "nearest integer; half ties earlier; exact rational enclosure retained, not propagated into covariance",
            ),
        ),
        (
            "validation_rounding",
            string("earliest floor, latest ceiling; no inward rounding"),
        ),
        (
            "projection_policy",
            string(
                "outward-rounded hull of ALL supplied hypotheses, including unsupported and unresolved candidates; no clock selection",
            ),
        ),
        ("hypotheses_complete", "true".into()),
        ("hypothesis_count", evaluated.support.len().to_string()),
        (
            "additional_session_count",
            evaluated.sessions.len().to_string(),
        ),
        (
            "supported_in_every_session_count",
            evaluated
                .support
                .iter()
                .filter(|s| s.supported_in_every_session())
                .count()
                .to_string(),
        ),
        ("disjoint_session_membership_checked", "true".into()),
        ("work_limit", work_limit.to_string()),
        ("work_consumed", evaluated.work_units.to_string()),
        (
            "work_remaining",
            (work_limit - evaluated.work_units).to_string(),
        ),
        ("clock_activated", "false".into()),
        ("continuous_rate_or_offset_certified", "false".into()),
        ("source_custody_verified", "false".into()),
        ("physical_calibration_verified", "false".into()),
        ("independent_clock_validation", "false".into()),
        ("coverage_or_effect_authority", "false".into()),
        (
            "model",
            string(
                "frozen affine clock hypotheses; separate constant-velocity feature per session; fixed pinhole cameras; nominal training times",
            ),
        ),
        (
            "excluded_uncertainties",
            string(
                "clock-rate variation, training timestamp and rounding uncertainty, camera calibration, association, rolling shutter, acceleration and shared-mode errors",
            ),
        ),
    ] {
        out.field(name, &value, work)?;
    }
    out.name("cameras", work)?;
    out.array(&common.cameras, work, |out, c, work| {
        out.raw(
            &object(&[
                ("camera", string(&c.id.to_string())),
                ("clock", string(&c.clock.to_string())),
                ("calibration_digest", string(&c.calibration.to_text())),
                ("image_domain", string(&c.image_domain.to_text())),
            ]),
            work,
        )
    })?;
    out.name("search", work)?;
    scan(&mut out, 0, &query.search, &evaluated.search, work)?;
    out.name("sessions", work)?;
    out.array(&evaluated.sessions, work, |out, session, work| {
        let input = query
            .sessions
            .iter()
            .find(|q| q.id == session.id)
            .ok_or_else(|| failure("scan", "native clock validation session identity changed"))?;
        scan(out, session.id, &input.query, &session.scan, work)
    })?;
    out.name("hypothesis_support", work)?;
    out.array(&evaluated.support, work, |out, support, work| {
        out.raw("{", work)?;
        out.field("hypothesis", &hypothesis(support.hypothesis), work)?;
        out.field(
            "search_supported",
            &support.search_supported.to_string(),
            work,
        )?;
        out.field(
            "supported_in_every_session",
            &support.supported_in_every_session().to_string(),
            work,
        )?;
        out.name("sessions", work)?;
        out.array(&support.sessions, work, |out, (id, supported), work| {
            out.raw(
                &object(&[
                    ("session_id", string(&id.to_string())),
                    ("supported", supported.to_string()),
                ]),
                work,
            )
        })?;
        out.raw("}", work)
    })?;
    out.name("projections", work)?;
    out.array(&evaluated.projections, work, |out, projection, work| {
        out.raw("{", work)?;
        out.field("id", &string(&projection.request.id.to_string()), work)?;
        out.field(
            "target_interval_ns",
            &times(projection.request.target_interval_ns),
            work,
        )?;
        out.field(
            "reference_envelope_ns",
            &times(projection.reference_envelope_ns),
            work,
        )?;
        out.field(
            "observation_window",
            &string(if projection.containing_session_ids.is_empty() {
                "outside_declared_sessions"
            } else {
                "within_declared_session"
            }),
            work,
        )?;
        out.name("containing_session_ids", work)?;
        out.array(&projection.containing_session_ids, work, |out, id, work| {
            out.raw(&string(&id.to_string()), work)
        })?;
        out.name("mappings", work)?;
        out.array(
            &projection.mappings,
            work,
            |out, (candidate, interval), work| {
                out.raw(
                    &object(&[
                        ("hypothesis", hypothesis(*candidate)),
                        ("reference_interval_ns", times(*interval)),
                    ]),
                    work,
                )
            },
        )?;
        out.raw("}", work)
    })?;
    out.raw("}", work)?;
    checkpoint(work)?;
    let response = object(&[
        ("schema", string(response_schema)),
        (
            "report_digest",
            string(&ContentDigest::sha256(out.bytes.as_bytes()).to_text()),
        ),
        ("report", out.bytes),
    ]);
    checkpoint(work)?;
    if response.len() >= output_limit {
        return Err(failure("limit", "complete response exceeds output bound"));
    }
    Ok(response)
}

#[cfg(test)]
pub(super) fn render_with_limit(
    query: &Query,
    evaluated: &ClockValidationReport,
    digest: ContentDigest,
    work_limit: u64,
    input_bytes: usize,
    work: &mut WorkBudget<'_>,
    output_limit: usize,
) -> Result<String> {
    render_bounded(
        query,
        evaluated,
        digest,
        work_limit,
        input_bytes,
        work,
        output_limit,
        false,
    )
}

pub(super) fn render_replay(
    query: &Query,
    evaluated: &ClockValidationReport,
    digest: ContentDigest,
    available_work: u64,
    input_bytes: usize,
    work: &mut WorkBudget<'_>,
) -> Result<String> {
    render_bounded(
        query,
        evaluated,
        digest,
        available_work,
        input_bytes,
        work,
        MAX_REPORT_BYTES,
        true,
    )
}
