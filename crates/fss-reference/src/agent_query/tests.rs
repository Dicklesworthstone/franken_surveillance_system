#![forbid(unsafe_code)]
//! Compiler tests use an empty verified on-disk deployment plus explicitly synthetic
//! in-memory event rows. They do not claim those rows were physically observed or published.

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use fss_core::{
    AgentOperation, BudgetVector, CaptureInterval, Completeness, ContentDigest, ContextAuthority,
    DecisionPath, EventEvidence, EvidenceClass, EvidenceEdgeRelation, OperationId,
    ProbabilityInterval, RootAuthoritySpec, SensorTamperStatus,
};

use super::*;
use crate::agent_orient::{OrientLimits, read_deployment};
use crate::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn new(tag: &str) -> TestResult<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-agent-query-{tag}-{}-{attempt}", std::process::id(),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("query test directory capacity".into())
    }
}

impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture(tag: &str, count: usize) -> TestResult<(OwnedDirectory, DeploymentSnapshot)> {
    let directory = OwnedDirectory::new(tag)?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:query-unit".to_owned(),
        operation_id: OperationId::parse("operation:query-unit")?,
        principal: "operator:query-unit".to_owned(),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".to_owned(),
        retention_scope: "retention:ephemeral".to_owned(),
        anchor_universe: ContentDigest::sha256(b"query-unit"),
        generation: 1,
    })?;
    let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
        &authority, directory.0.join("cx"),
    )?);
    let root = directory.0.join("deployment");
    drop(ReferenceDeployment::open(&root, "site:query-unit", &cx)?);
    let mut snapshot = read_deployment(&root, &OrientLimits::default())?;
    snapshot.latest_evidence_time = TimestampNs(100);
    for index in 0..count {
        snapshot.events.push(record(index)?);
    }
    Ok((directory, snapshot))
}

fn record(index: usize) -> TestResult<RetainedEvent> {
    let event = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_owned(),
        event_id: EventId::parse(format!("event:query:{index:04}"))?,
        revision: 1,
        supersedes: None,
        state: EventState::Hypothesized,
        kind: EventKind::UnknownPresence,
        interval: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
        uncertainty_reason: None,
        zone_ids: vec!["door".to_owned()],
        track_ids: Vec::new(),
        probability: ProbabilityInterval::new(0.0, 1.0)?,
        evidence: Vec::new(),
        model_receipts: Vec::new(),
        decision_path: DecisionPath {
            policy_generation: ContentDigest::sha256(b"query-policy"),
            fingerprint: ContentDigest::sha256(b"query-hypothesis"),
            abstained: true,
            abstention_reason: Some("synthetic hypothesis only".to_owned()),
        },
    };
    event.verify()?;
    Ok(RetainedEvent {
        revisions: vec![event.clone()],
        event_root: ContentDigest::sha256(format!("root-{index}").as_bytes()),
        revision_digest: event.canonical_digest(EventHypothesis::SCHEMA),
        committed_sequence: 0,
        tamper: SensorTamperStatus::default(),
        object_bytes: 100,
        object_reads: 1,
        event,
    })
}

fn request(size: u32) -> TestResult<EventQueryRequest> {
    Ok(EventQueryRequest {
        filter: EventQueryFilter::default(),
        principal: PrincipalId::parse("principal:query-unit")?,
        max_entries: size,
        expected_anchor: None,
        continuation: None,
    })
}

fn next(query: &DeploymentQuery) -> TestResult<String> {
    Ok(query.page.next_cursor.as_ref().ok_or("expected next query page")?.token().to_owned())
}

#[test]
fn empty_query_distinguishes_index_exhaustion_from_physical_absence() -> TestResult {
    let (_directory, snapshot) = fixture("empty", 0)?;
    let query = query_deployment(&snapshot, &request(1)?)?;
    assert_eq!(query.scanned_events, 0);
    assert_eq!(query.matched_events, 0);
    assert!(query.events.is_empty());
    assert!(query.page.next_cursor.is_none());
    assert_eq!(query.coverage().stop_reason, "committed_index_exhausted");
    assert!(!query.coverage().not_observable_domain.is_empty());
    assert_eq!(query.epistemic().propositions[1].state, KnowledgeState::Unknown);
    assert_eq!(query.admission.completeness(), Completeness::Bounded);
    assert_eq!(query.plan.operation(), AgentOperation::Query);
    Ok(())
}

#[test]
fn exact_pages_deliver_each_record_once_and_replay_identically() -> TestResult {
    let (_directory, snapshot) = fixture("pages", 5)?;
    let mut request = request(2)?;
    let first = query_deployment(&snapshot, &request)?;
    assert_eq!(first, query_deployment(&snapshot, &request)?);
    assert_eq!(first.events.len(), 2);
    assert_eq!(first.remaining_events(), 3);
    assert_eq!(first.coverage().omitted_count, 3);
    let mut ids = Vec::new();
    let mut previous_cursor = None;
    loop {
        let page = query_deployment(&snapshot, &request)?;
        page.page.verify()?;
        assert_eq!(page.plan.plan_digest(), first.plan.plan_digest());
        assert_eq!(page.selection_witness, first.selection_witness);
        assert_eq!(page.cursor.predecessor_digest, previous_cursor);
        ids.extend(page.events.iter().map(|row| row.event.event_id.as_str().to_owned()));
        previous_cursor = Some(page.cursor.cursor_digest);
        match &page.page.next_cursor {
            Some(next) => request.continuation = Some(next.token().to_owned()),
            None => {
                assert_eq!(page.remaining_events(), 0);
                break;
            }
        }
    }
    assert_eq!(ids, snapshot.events.iter().map(|row| row.event.event_id.as_str().to_owned())
        .collect::<Vec<_>>());
    Ok(())
}

#[test]
fn filters_are_conjunctive_exact_and_closed_interval_overlap() -> TestResult {
    let (_directory, mut snapshot) = fixture("filters", 3)?;
    snapshot.events[1].event.kind = EventKind::BenignRoutine;
    snapshot.events[2].event.zone_ids = vec!["Door".to_owned()];
    let mut request = request(10)?;
    request.filter.zone = Some("door".to_owned());
    request.filter.kind = Some(EventKind::UnknownPresence);
    request.filter.state = Some(EventState::Hypothesized);
    request.filter.from_ns = Some(20);
    request.filter.through_ns = Some(20);
    let query = query_deployment(&snapshot, &request)?;
    assert_eq!(query.events.len(), 1);
    assert_eq!(query.events[0].event.event_id, snapshot.events[0].event.event_id);
    request.filter.from_ns = Some(21);
    request.filter.through_ns = None;
    assert_eq!(query_deployment(&snapshot, &request)?.matched_events, 0);
    request.filter.from_ns = None;
    request.filter.through_ns = Some(10);
    assert_eq!(query_deployment(&snapshot, &request)?.matched_events, 1);
    request.filter.through_ns = Some(9);
    assert_eq!(query_deployment(&snapshot, &request)?.matched_events, 0);
    request.filter.through_ns = None;
    request.filter.event_id = Some(snapshot.events[1].event.event_id.clone());
    assert_eq!(query_deployment(&snapshot, &request)?.matched_events, 0);
    Ok(())
}

#[test]
fn filter_time_comparisons_do_not_overflow_at_i128_extremes() -> TestResult {
    let mut row = record(0)?;
    row.event.interval = CaptureInterval::new(TimestampNs(i128::MIN), TimestampNs(i128::MAX))?;
    let mut filter = EventQueryFilter {
        from_ns: Some(i128::MAX),
        through_ns: Some(i128::MAX),
        ..EventQueryFilter::default()
    };
    assert!(filter.matches(&row.event));
    filter.from_ns = Some(i128::MIN);
    filter.through_ns = Some(i128::MIN);
    assert!(filter.matches(&row.event));
    Ok(())
}

#[test]
fn only_latest_revision_is_filtered_and_hypothesis_state_is_not_promoted() -> TestResult {
    let (_directory, mut snapshot) = fixture("latest", 1)?;
    let row = &mut snapshot.events[0];
    let prior = row.event.clone();
    row.event.revision = 2;
    row.event.supersedes = Some(row.revision_digest);
    row.event.kind = EventKind::BenignRoutine;
    row.event.state = EventState::Indeterminate;
    row.event.evidence.push(EventEvidence {
        digest: ContentDigest::sha256(b"uncertain-evidence"),
        class: EvidenceClass::Derived,
        failure_domain: "sensor:a".to_owned(),
        supports: false,
        relation: EvidenceEdgeRelation::Contradicts,
        capsule_digest: None,
        identity_digest: None,
    });
    row.revisions = vec![prior, row.event.clone()];
    row.revision_digest = row.event.canonical_digest(EventHypothesis::SCHEMA);
    let mut request = request(1)?;
    request.filter.kind = Some(EventKind::UnknownPresence);
    assert_eq!(query_deployment(&snapshot, &request)?.matched_events, 0);
    request.filter.kind = Some(EventKind::BenignRoutine);
    let query = query_deployment(&snapshot, &request)?;
    assert_eq!(query.events[0].event, snapshot.events[0].event);
    assert_eq!(query.events[0].event.state, EventState::Indeterminate);
    assert!(query.epistemic().propositions[2].statement.contains("contradictory_edges=1"));
    assert!(query.epistemic().propositions[2].statement.contains("not the hypothesis's physical truth"));
    Ok(())
}

#[test]
fn order_is_canonical_and_cursor_cannot_be_reused_for_a_different_query() -> TestResult {
    let (_directory, mut snapshot) = fixture("binding", 4)?;
    let original = request(1)?;
    let first = query_deployment(&snapshot, &original)?;
    snapshot.events.reverse();
    assert_eq!(first, query_deployment(&snapshot, &original)?);
    let mut resumed = original.clone();
    resumed.continuation = Some(next(&first)?);
    assert_eq!(query_deployment(&snapshot, &resumed)?.cursor.position, 1);
    for variant in 0..4 {
        let mut changed = resumed.clone();
        match variant {
            0 => changed.max_entries = 2,
            1 => changed.principal = PrincipalId::parse("principal:someone-else")?,
            2 => changed.filter.zone = Some("door".to_owned()),
            _ => changed.filter.from_ns = Some(0),
        }
        assert!(matches!(query_deployment(&snapshot, &changed),
            Err(QueryError::Continuation(ContinuationError::WrongStream))));
    }
    let token = resumed.continuation.as_mut().ok_or("continuation")?;
    let last = token.pop().ok_or("token character")?;
    token.push(if last == 'a' { 'b' } else { 'a' });
    assert!(matches!(query_deployment(&snapshot, &resumed),
        Err(QueryError::Continuation(ContinuationError::WrongStream))));
    Ok(())
}

#[test]
fn authority_and_effect_only_advances_invalidate_old_pages() -> TestResult {
    let (_directory, snapshot) = fixture("advance", 3)?;
    let mut request = request(1)?;
    let first = query_deployment(&snapshot, &request)?;
    request.continuation = Some(next(&first)?);
    let mut changed = snapshot.clone();
    changed.anchor.commit_sequence += 1;
    changed.position.commit_sequence += 1;
    assert!(query_deployment(&changed, &request).is_err());
    let mut changed = snapshot.clone();
    changed.position.effect_records = Some(1);
    changed.effect_journal_present = true;
    changed.effect_journal_root = ContentDigest::sha256(b"new-effect-record");
    assert_eq!(changed.anchor, snapshot.anchor);
    assert!(query_deployment(&changed, &request).is_err());
    request.expected_anchor = AnchorToken::parse(&first.anchor_token);
    assert!(matches!(query_deployment(&changed, &request), Err(QueryError::AnchorChanged)));
    assert!(query_deployment(&snapshot, &request).is_ok());
    Ok(())
}

#[test]
fn complete_index_content_binds_cursors_even_when_a_changed_row_is_excluded() -> TestResult {
    let (_directory, mut snapshot) = fixture("excluded-binding", 3)?;
    snapshot.events[2].event.zone_ids = vec!["garage".to_owned()];
    let mut request = request(1)?;
    request.filter.zone = Some("door".to_owned());
    let first = query_deployment(&snapshot, &request)?;
    request.continuation = Some(next(&first)?);
    snapshot.events[2].event.kind = EventKind::CovertApproach;
    assert!(matches!(query_deployment(&snapshot, &request),
        Err(QueryError::Continuation(ContinuationError::WrongStream))));
    Ok(())
}

#[test]
fn invalid_and_duplicate_rows_are_refused_even_outside_the_filter() -> TestResult {
    let (_directory, mut snapshot) = fixture("bad-record", 2)?;
    let mut request = request(1)?;
    request.filter.zone = Some("not-present".to_owned());
    snapshot.events[1].event.revision = 0;
    assert!(matches!(query_deployment(&snapshot, &request), Err(QueryError::InvalidRecord)));
    snapshot.events[1] = snapshot.events[0].clone();
    assert!(matches!(query_deployment(&snapshot, &request), Err(QueryError::InvalidRecord)));
    Ok(())
}

#[test]
fn limits_are_checked_before_filtering_and_expiry_overflow_is_refused() -> TestResult {
    let (_directory, mut snapshot) = fixture("bounds", MAX_QUERY_EVENTS + 1)?;
    let mut request = request(1)?;
    request.filter.zone = Some("not-present".to_owned());
    assert!(matches!(query_deployment(&snapshot, &request), Err(QueryError::TooManyEvents)));
    snapshot.events.pop();
    assert!(query_deployment(&snapshot, &request).is_ok());
    for size in [0, MAX_QUERY_ENTRIES + 1, u32::MAX] {
        request.max_entries = size;
        assert!(matches!(query_deployment(&snapshot, &request),
            Err(QueryError::InvalidRequest(_))));
    }
    request.max_entries = 1;
    request.filter.from_ns = Some(20);
    request.filter.through_ns = Some(10);
    assert!(request.validate().is_err());
    request.filter = EventQueryFilter::default();
    request.continuation = Some("continuation:".repeat(100));
    assert!(request.validate().is_err());
    request.continuation = None;
    snapshot.latest_evidence_time = TimestampNs(i128::MAX);
    assert!(matches!(query_deployment(&snapshot, &request), Err(QueryError::InvalidRequest(_))));
    Ok(())
}
