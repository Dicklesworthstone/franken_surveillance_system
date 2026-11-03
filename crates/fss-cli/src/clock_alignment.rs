#![forbid(unsafe_code)]
//! Shared strict clock-query admission and native finite-inventory replay.
//!
//! Input pins and camera declarations remain assertions. This owner performs no source I/O,
//! grants no clock activation, and never removes an unsupported mapping from a time hull.

#[path = "bin/fss-clock-align/drift.rs"]
mod drift;
#[path = "bin/fss-clock-align/input.rs"]
pub mod input;
#[path = "bin/fss-clock-align/report.rs"]
mod report;
#[path = "bin/fss-clock-align/validation.rs"]
mod validation;

use crate::json_input::parse;
use fss_core::ContentDigest;
use fss_geometry::{WorkBudget, temporal_alignment::scan_clock_offsets};

/// Maximum exact input document, before parsing or cloning bounded session definitions.
pub const MAX_INPUT_BYTES: usize = 1024 * 1024;
/// Maximum complete standalone or embedded replay response, including final newline.
pub const MAX_REPORT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug)]
pub struct Failure {
    pub code: &'static str,
    pub detail: String,
}
pub type Result<T> = std::result::Result<T, Failure>;
pub fn failure(code: &'static str, detail: impl Into<String>) -> Failure {
    let code = match code {
        "input" => "ERR-CLOCK-ALIGNMENT-INPUT-001",
        "io" => "ERR-CLOCK-ALIGNMENT-IO-001",
        "limit" => "ERR-CLOCK-ALIGNMENT-LIMIT-001",
        "scan" => "ERR-CLOCK-ALIGNMENT-SCAN-001",
        "output" => "ERR-CLOCK-ALIGNMENT-OUTPUT-001",
        "cancelled" => "ERR-CLOCK-ALIGNMENT-CANCELLED-001",
        _ => "ERR-CLOCK-ALIGNMENT-AUTHORITY-001",
    };
    Failure {
        code,
        detail: detail.into(),
    }
}

#[cfg(test)]
fn analyze(bytes: &[u8], expected: ContentDigest, work_limit: u64) -> Result<(String, bool)> {
    analyze_with_probe(bytes, expected, work_limit, &|| false)
}
pub fn analyze_with_probe(
    bytes: &[u8],
    expected: ContentDigest,
    work_limit: u64,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<(String, bool)> {
    if bytes.len() > MAX_INPUT_BYTES || ContentDigest::sha256(bytes) != expected {
        return Err(failure(
            "input",
            "input size or independent digest mismatch",
        ));
    }
    let value =
        parse(std::str::from_utf8(bytes).map_err(|_| failure("input", "input is not UTF-8"))?)
            .map_err(|_| failure("input", "invalid or oversized JSON"))?;
    match value
        .object()
        .and_then(|fields| fields.get("schema"))
        .and_then(|value| value.text())
    {
        Some(drift::SCHEMA) => return drift::analyze(&value, expected, work_limit, bytes.len()),
        Some(validation::SCHEMA) => {
            return validation::analyze(&value, expected, work_limit, bytes.len(), cancelled);
        }
        _ => {}
    }
    let query = input::query(&value)?;
    let mut budget = WorkBudget::new(work_limit);
    let scan = scan_clock_offsets(
        query.pair,
        &query.training,
        &query.validation,
        &query.offsets,
        query.options,
        &mut budget,
    )
    .map_err(|e| failure("scan", e.to_string()))?;
    let supported = scan
        .trials
        .iter()
        .any(|trial| trial.consistent_for_all_capture_times());
    let report = report::render(&query, &scan, expected, work_limit, bytes.len());
    if report.len() >= MAX_REPORT_BYTES {
        return Err(failure("limit", "complete report exceeds output bound"));
    }
    Ok((report, supported))
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}
impl std::error::Error for Failure {}

/// Strictly admitted original query, before native replay under the caller's shared work.
/// Its private contents cannot be replaced with a serialized claim of a successful scan.
pub struct ClockValidationQuery {
    query: validation::Query,
    digest: ContentDigest,
    input_bytes: usize,
}

impl ClockValidationQuery {
    /// Check the independent byte pin, bounded JSON and every original session/source field.
    /// Parsing and hashing are charged to the same caller budget as the later native replay.
    pub fn parse_pinned(
        bytes: &[u8],
        expected: ContentDigest,
        work: &mut WorkBudget<'_>,
    ) -> Result<Self> {
        validation::checkpoint(work)?;
        if bytes.is_empty() || bytes.len() > MAX_INPUT_BYTES {
            return Err(failure(
                "input",
                "clock query exceeds its complete byte bound",
            ));
        }
        work.charge(4096 + bytes.len() as u64 * 4)
            .map_err(work_failure)?;
        if ContentDigest::sha256(bytes) != expected {
            return Err(failure(
                "input",
                "clock query differs from its independent pin",
            ));
        }
        let value = parse(
            std::str::from_utf8(bytes).map_err(|_| failure("input", "clock query is not UTF-8"))?,
        )
        .map_err(|_| failure("input", "clock query is malformed or exceeds JSON bounds"))?;
        let query = validation::query(&value)?;
        validation::checkpoint(work)?;
        Ok(Self {
            query,
            digest: expected,
            input_bytes: bytes.len(),
        })
    }

    /// The actual original nominal camera models, not only their caller labels.
    pub fn cameras(&self) -> &[input::Camera; 2] {
        &self.query.search.common.cameras
    }
    /// Exact declared world-frame evidence pin; downstream callers must bind its meaning.
    pub fn world_basis(&self) -> ContentDigest {
        self.query.search.common.world
    }
    /// Unchanged logical camera and local clock generation inventory.
    pub fn pair(&self) -> fss_geometry::temporal_alignment::ClockAlignmentPair {
        self.query.search.common.pair
    }
    /// Every original target interval request. No downstream source may substitute an interval.
    pub fn projections(
        &self,
    ) -> &[fss_geometry::temporal_alignment::drift::validation::ClockProjectionRequest] {
        &self.query.projections
    }
    /// Independently checked original input bytes, not a success/custody certificate.
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }

    /// Re-run all original native scans and projections using this SAME nonrefillable budget.
    pub fn evaluate(self, work: &mut WorkBudget<'_>) -> Result<ClockValidationReplay> {
        let available_work = work.remaining();
        let report = validation::evaluate(&self.query, work)?;
        Ok(ClockValidationReplay {
            query: self,
            report,
            available_work,
        })
    }
}

/// Immutable native replay with complete diagnostics and an unpruned projection inventory.
/// Only evaluation of the original strict query constructs this value.
pub struct ClockValidationReplay {
    query: ClockValidationQuery,
    report: fss_geometry::temporal_alignment::drift::validation::ClockValidationReport,
    available_work: u64,
}
impl ClockValidationReplay {
    /// Original query scope retained by the replay.
    pub fn query(&self) -> &ClockValidationQuery {
        &self.query
    }
    /// Borrow every original trial, session and interval; none is selected for authority.
    pub fn report(
        &self,
    ) -> &fss_geometry::temporal_alignment::drift::validation::ClockValidationReport {
        &self.report
    }
    /// Complete diagnostics under the embedded replay profile. Work allowance means the
    /// caller's remaining allowance at native scan entry; no child budget is created.
    pub fn render(&self, work: &mut WorkBudget<'_>) -> Result<String> {
        validation::render_replay(
            &self.query.query,
            &self.report,
            self.query.digest,
            self.available_work,
            self.query.input_bytes,
            work,
        )
    }
}

fn work_failure(error: fss_geometry::GeometryError) -> Failure {
    match error {
        fss_geometry::GeometryError::Cancelled => failure("cancelled", "clock replay cancelled"),
        _ => failure("limit", "clock replay exhausted shared work or allocation"),
    }
}

#[cfg(test)]
#[path = "clock_alignment/tests.rs"]
mod tests;
