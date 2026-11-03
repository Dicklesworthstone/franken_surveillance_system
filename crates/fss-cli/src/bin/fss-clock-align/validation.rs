#![forbid(unsafe_code)]
//! Frozen clock hypotheses, disjoint source membership, and complete time envelopes.

use std::collections::BTreeSet;

use crate::json_input::Value;
use fss_core::ContentDigest;
use fss_geometry::temporal_alignment::drift::validation::{
    ClockProjectionRequest, ClockValidationError, ClockValidationReport, ClockValidationSession,
    MAX_CLOCK_INTERVAL_PROJECTIONS, MAX_CLOCK_VALIDATION_SESSIONS, validate_clock_sessions,
};
use fss_geometry::{GeometryError, WorkBudget};

use super::{Result, drift, failure};

#[path = "validation/report.rs"]
mod report;
#[cfg(test)]
#[path = "validation/tests.rs"]
mod tests;

pub const SCHEMA: &str = "fss.clock_validation_query.v1";

struct Session {
    id: u64,
    query: drift::Query,
}

pub(super) struct Query {
    pub(super) search: drift::Query,
    sessions: Vec<Session>,
    pub(super) projections: Vec<ClockProjectionRequest>,
}

fn positive(value: &Value) -> Result<u64> {
    value
        .integer()
        .and_then(|v| u64::try_from(v).ok())
        .filter(|v| *v != 0)
        .ok_or_else(|| {
            failure(
                "input",
                "session and projection IDs must be nonzero u64 integers",
            )
        })
}

pub(super) fn query(value: &Value) -> Result<Query> {
    let original = value
        .object()
        .ok_or_else(|| failure("input", "expected clock validation object"))?;
    let keys = [
        "schema",
        "world_basis",
        "association_evidence",
        "reference_camera",
        "target_camera",
        "target_anchor_ns",
        "hypotheses",
        "fit_options",
        "training",
        "validation",
        "sessions",
        "projections",
    ];
    if original.len() != keys.len()
        || keys.iter().any(|key| !original.contains_key(*key))
        || original.get("schema").and_then(Value::text) != Some(SCHEMA)
    {
        return Err(failure(
            "input",
            "missing, unknown or unsupported clock validation field",
        ));
    }
    let sessions = original
        .get("sessions")
        .and_then(Value::array)
        .filter(|v| !v.is_empty() && v.len() <= MAX_CLOCK_VALIDATION_SESSIONS)
        .ok_or_else(|| {
            failure(
                "input",
                "clock validation needs one through eight additional sessions",
            )
        })?;
    let requests = original
        .get("projections")
        .and_then(Value::array)
        .filter(|v| v.len() <= MAX_CLOCK_INTERVAL_PROJECTIONS)
        .ok_or_else(|| {
            failure(
                "input",
                "clock validation admits at most 128 interval projections",
            )
        })?;

    // Each session uses the same strict drift reader and the SAME caller-supplied camera,
    // clock, world, hypothesis and fit definitions. A session cannot override any of them.
    // These temporary documents are not hashed, published, or substituted for the input pin.
    let mut shared = original.clone();
    shared.remove("sessions");
    shared.remove("projections");
    shared.insert("schema".into(), Value::Text(drift::SCHEMA.into()));
    let search = drift::query(&Value::Object(shared.clone()))?;
    let mut parsed = Vec::new();
    parsed
        .try_reserve_exact(sessions.len())
        .map_err(|_| failure("limit", "session allocation refused"))?;
    let mut ids = BTreeSet::new();
    for session in sessions {
        let fields = session
            .object()
            .filter(|f| {
                f.len() == 4
                    && ["id", "association_evidence", "training", "validation"]
                        .iter()
                        .all(|k| f.contains_key(*k))
            })
            .ok_or_else(|| {
                failure(
                    "input",
                    "session needs only id, association_evidence, training and validation",
                )
            })?;
        let id = positive(&fields["id"])?;
        if !ids.insert(id) {
            return Err(failure(
                "input",
                "duplicate clock validation session identity",
            ));
        }
        for key in ["association_evidence", "training", "validation"] {
            shared.insert(key.into(), fields[key].clone());
        }
        parsed.push(Session {
            id,
            query: drift::query(&Value::Object(shared.clone()))?,
        });
    }
    parsed.sort_by_key(|session| session.id);

    // Changing timestamps, camera IDs, evidence labels or session names must not turn the
    // same submitted source into a fresh passage. This profile requires distinct source and
    // evidence pins across the COMPLETE inventory; exposure names are scoped to a camera.
    let mut exposures = BTreeSet::new();
    let mut sources = BTreeSet::new();
    let mut evidence = BTreeSet::new();
    for query in std::iter::once(&search).chain(parsed.iter().map(|session| &session.query)) {
        for source in &query.common.sources {
            if !exposures.insert((source.camera, source.exposure.clone()))
                || !sources.insert(source.source)
                || !evidence.insert(source.evidence)
            {
                return Err(failure(
                    "input",
                    "reused source, evidence or exposure across clock validation observations",
                ));
            }
        }
    }

    let mut projections = Vec::new();
    projections
        .try_reserve_exact(requests.len())
        .map_err(|_| failure("limit", "projection allocation refused"))?;
    let mut ids = BTreeSet::new();
    for request in requests {
        let fields = request
            .object()
            .filter(|f| {
                f.len() == 2 && f.contains_key("id") && f.contains_key("target_interval_ns")
            })
            .ok_or_else(|| failure("input", "projection needs only id and target_interval_ns"))?;
        let id = positive(&fields["id"])?;
        let times = fields["target_interval_ns"]
            .array()
            .filter(|v| v.len() == 2)
            .ok_or_else(|| failure("input", "target interval needs two exact integer bounds"))?;
        let start = times[0]
            .integer()
            .ok_or_else(|| failure("input", "invalid target interval start"))?;
        let end = times[1]
            .integer()
            .ok_or_else(|| failure("input", "invalid target interval end"))?;
        if start > end || !ids.insert(id) {
            return Err(failure(
                "input",
                "reversed interval or duplicate projection identity",
            ));
        }
        projections.push(ClockProjectionRequest {
            id,
            target_interval_ns: [start, end],
        });
    }
    Ok(Query {
        search,
        sessions: parsed,
        projections,
    })
}

pub(super) fn evaluate(query: &Query, work: &mut WorkBudget<'_>) -> Result<ClockValidationReport> {
    let mut sessions = Vec::new();
    sessions
        .try_reserve_exact(query.sessions.len())
        .map_err(|_| failure("limit", "session view allocation refused"))?;
    for session in &query.sessions {
        sessions.push(ClockValidationSession {
            id: session.id,
            training: &session.query.common.training,
            validation: &session.query.common.validation,
        });
    }
    validate_clock_sessions(
        query.search.common.pair,
        query.search.target_anchor_ns,
        &query.search.common.training,
        &query.search.common.validation,
        &sessions,
        &query.search.hypotheses,
        &query.projections,
        query.search.common.options,
        work,
    )
    .map_err(native_failure)
}

fn native_failure(error: ClockValidationError) -> super::Failure {
    // The native owners wrap GeometryError through alignment, drift, validation and fit
    // layers. Inspect that finite typed cause chain so a late cancellation is never turned
    // into an ordinary unresolved clock or a generic malformed-input error.
    let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    for _ in 0..8 {
        let Some(current) = cause else {
            break;
        };
        if current.downcast_ref::<GeometryError>() == Some(&GeometryError::Cancelled) {
            return failure(
                "cancelled",
                "clock validation cancelled before a complete report",
            );
        }
        if current.downcast_ref::<GeometryError>() == Some(&GeometryError::BudgetExhausted) {
            return failure(
                "limit",
                "clock validation exhausted its shared work allowance",
            );
        }
        cause = current.source();
    }
    failure("scan", error.to_string())
}

pub(super) fn checkpoint(work: &mut WorkBudget<'_>) -> Result<()> {
    work.charge(0).map_err(|error| match error {
        GeometryError::Cancelled => failure(
            "cancelled",
            "clock validation cancelled before a complete report",
        ),
        _ => failure("scan", error.to_string()),
    })
}

pub fn analyze(
    value: &Value,
    digest: ContentDigest,
    work_limit: u64,
    input_bytes: usize,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<(String, bool)> {
    let mut work = WorkBudget::with_cancellation_probe(work_limit, cancelled);
    checkpoint(&mut work)?;
    let query = query(value)?;
    let evaluated = evaluate(&query, &mut work)?;
    let supported = evaluated
        .support
        .iter()
        .any(|row| row.supported_in_every_session());
    let report = report::render(
        &query,
        &evaluated,
        digest,
        work_limit,
        input_bytes,
        &mut work,
    )?;
    Ok((report, supported))
}

pub(super) fn render_replay(
    query: &Query,
    report: &ClockValidationReport,
    digest: ContentDigest,
    available_work: u64,
    input_bytes: usize,
    work: &mut WorkBudget<'_>,
) -> Result<String> {
    report::render_replay(query, report, digest, available_work, input_bytes, work)
}
