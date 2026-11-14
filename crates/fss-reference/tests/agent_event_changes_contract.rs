#![forbid(unsafe_code)]
//! Real immutable event publications, exact predecessor comparison and late read refusal.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use fss_core::{
    AgentView, CaptureInterval, ContentDigest, ContextAuthority, DecisionPath, EventEvidence,
    EventHypothesis, EventId, EventKind, EventState, EvidenceClass, EvidenceEdgeRelation,
    ExplainQuestion, OperationId, PrincipalId, ProbabilityInterval, RootAuthoritySpec, TimestampNs,
};
use fss_object::SPOOL_OBJECTS_DIR;
use fss_publication::{LOCAL_SPOOL_DIR, LOCAL_TOMBSTONES_DIR, TOMBSTONE_RECORD_SUFFIX};
use fss_reference::agent_event_changes::{
    EVENT_CHANGES_SCHEMA, EventChangesErrorKind, EventChangesLimits, EventChangesRequest,
    explain_event_changes_in_deployment, prepare_event_changes_in_deployment,
};
use fss_reference::agent_follow::AnchorToken;
use fss_reference::agent_orient::{OrientRequest, explain_event, orient_deployment};
use fss_reference::reference_deployment::RELATIVE_PATH_EFFECTS;
use fss_reference::retained_source::{ImmutableRetainedSource, verify_event_lineage};
use fss_reference::{
    ReferenceDeployment, ReferencePolicyAction, ReferencePolicyDecision, ReplayCx,
};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:event-changes-contract";
const PRINCIPAL: &str = "principal:event-changes-contract";
const SOURCE: &[u8] = b"PRIVATE_ORIGINAL_MUST_NOT_BE_OPENED_BY_METADATA_COMPARISON";
const NS: i128 = 9_007_199_254_740_993;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for sequence in 0..100 {
            let root = std::env::temp_dir().join(format!(
                "fss-event-changes-{label}-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => return Ok(Self(root)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("temporary directory bound exhausted".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    _directory: Directory,
    root: PathBuf,
    from: EventHypothesis,
    to: EventHypothesis,
    roots: [ContentDigest; 2],
    payloads: [ContentDigest; 2],
    writer: ReplayCx,
}

fn context(root: &Path, limits: EventChangesLimits, write: bool) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:event-changes-contract".into(),
        operation_id: OperationId::parse("operation:event-changes-contract")?,
        principal: PRINCIPAL.into(),
        capabilities: vec!["ADP-REPLAY-001".into(), "CAP-AGENT-EXPLAIN-001".into()],
        deadline: None,
        priority: 10,
        budgets: limits.allowance()?,
        privacy_scope: "privacy:internal".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    assert!(!authority.has_capability(fss_core::RuntimeGrant::ReadMedia.as_str()));
    Ok(if write {
        ReplayCx::from_context_authority(&authority, root)?
    } else {
        ReplayCx::from_context_authority_read_only(&authority, root)?
    })
}

impl Fixture {
    fn new(label: &str) -> Test<Self> {
        Self::modified(label, |_| {})
    }

    fn modified(label: &str, mutate: impl FnOnce(&mut EventHypothesis)) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let writer = context(&root, EventChangesLimits::default(), true)?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &writer)?;
        let original = deployment.stage_payload(SOURCE)?;
        let old_counter = deployment.stage_payload(b"old contradictory metadata fixture")?;
        let new_counter = deployment.stage_payload(b"new contradictory metadata fixture")?;
        let old_model = deployment.stage_payload(b"old retained model receipt")?;
        let new_model = deployment.stage_payload(b"new retained model receipt")?;
        let from = EventHypothesis {
            schema: EventHypothesis::SCHEMA.into(),
            event_id: EventId::parse("event:changes-contract")?,
            revision: 1,
            supersedes: None,
            state: EventState::Hypothesized,
            kind: EventKind::UnknownPresence,
            interval: CaptureInterval::new(TimestampNs(NS), TimestampNs(NS + 10))?,
            uncertainty_reason: Some("Synthetic finite recording, no physical conclusion".into()),
            zone_ids: vec!["zone:old".into()],
            track_ids: vec!["track:old".into()],
            probability: ProbabilityInterval::new(0.0, 1.0)?,
            evidence: vec![
                EventEvidence {
                    digest: original,
                    class: EvidenceClass::Assertion,
                    failure_domain: "sensor:old".into(),
                    supports: false,
                    relation: EvidenceEdgeRelation::DerivedFrom,
                    capsule_digest: None,
                    identity_digest: None,
                },
                EventEvidence {
                    digest: old_counter,
                    class: EvidenceClass::Assertion,
                    failure_domain: "sensor:counter-old".into(),
                    supports: false,
                    relation: EvidenceEdgeRelation::Contradicts,
                    capsule_digest: None,
                    identity_digest: None,
                },
            ],
            model_receipts: vec![old_model],
            decision_path: DecisionPath {
                policy_generation: ContentDigest::sha256(b"old policy"),
                fingerprint: ContentDigest::sha256(b"old decision"),
                abstained: false,
                abstention_reason: None,
            },
        };
        let first = deployment.publish_event(
            &ReferencePolicyDecision {
                event: from.clone(),
                action: ReferencePolicyAction::Hold,
            },
            &writer,
        )?;
        let mut to = from.clone();
        to.revision = 2;
        to.supersedes = Some(from.revision_digest());
        to.state = EventState::Indeterminate;
        to.kind = EventKind::Unclassified;
        to.interval = CaptureInterval::new(TimestampNs(NS + 1), TimestampNs(NS + 13))?;
        to.uncertainty_reason =
            Some("Quoted \"field\", bracket ]}, slash \\, newline\n and Ω remain exact".into());
        to.zone_ids = vec!["zone:new".into(), "zone:other".into()];
        to.track_ids = vec!["track:new".into()];
        to.probability = ProbabilityInterval::with_calibration(
            0.125,
            0.875,
            ContentDigest::sha256(b"new calibration"),
        )?;
        to.evidence = vec![
            EventEvidence {
                digest: original,
                class: EvidenceClass::Derived,
                failure_domain: "sensor:new".into(),
                supports: true,
                relation: EvidenceEdgeRelation::Supports,
                capsule_digest: Some(ContentDigest::sha256(b"exact capsule identity")),
                identity_digest: Some(ContentDigest::sha256(b"exact source identity")),
            },
            EventEvidence {
                digest: new_counter,
                class: EvidenceClass::Assertion,
                failure_domain: "sensor:counter-new".into(),
                supports: false,
                relation: EvidenceEdgeRelation::Contradicts,
                capsule_digest: None,
                identity_digest: None,
            },
        ];
        to.model_receipts = vec![new_model];
        to.decision_path = DecisionPath {
            policy_generation: ContentDigest::sha256(b"new policy"),
            fingerprint: ContentDigest::sha256(b"new decision"),
            abstained: true,
            abstention_reason: Some("Contradiction remains unresolved".into()),
        };
        mutate(&mut to);
        let second = deployment.publish_event(
            &ReferencePolicyDecision {
                event: to.clone(),
                action: ReferencePolicyAction::Hold,
            },
            &writer,
        )?;
        drop(deployment);
        Ok(Self {
            _directory: directory,
            root,
            from,
            to,
            roots: [first.event_root, second.event_root],
            payloads: [first.event_object_digest, second.event_object_digest],
            writer,
        })
    }

    fn request(&self) -> Test<EventChangesRequest> {
        Ok(EventChangesRequest {
            event_id: self.to.event_id.clone(),
            from_revision_digest: self.from.revision_digest(),
            to_revision_digest: self.to.revision_digest(),
            principal: PrincipalId::parse(PRINCIPAL)?,
            expected_anchor: None,
            view: AgentView::Forensic,
            budget_tokens: Some(16_000),
        })
    }

    fn third(&self) -> Test<EventHypothesis> {
        let mut third = self.to.clone();
        third.revision = 3;
        third.supersedes = Some(self.to.revision_digest());
        third.interval.latest.0 += 1;
        let mut deployment = ReferenceDeployment::open(&self.root, SITE, &self.writer)?;
        deployment.publish_event(
            &ReferencePolicyDecision {
                event: third.clone(),
                action: ReferencePolicyAction::Hold,
            },
            &self.writer,
        )?;
        Ok(third)
    }
}


fn retain_liveness_metadata(fixture: &Fixture) -> Test<ContentDigest> {
    use fss_core::SensorId;
    use fss_reference::discovery::DiscoverReport;
    use fss_reference::discovery::retained_liveness::{
        DeviceEnrollment, retain_discovery_sweep,
    };
    use fss_reference::discovery::watchdog::DeviceClass;

    let enrollment = DeviceEnrollment::new(
        std::net::Ipv4Addr::new(192, 0, 2, 10),
        SensorId::parse("sensor:metadata-revalidation")?,
        DeviceClass::Onvif,
    )?;
    let mut deployment = ReferenceDeployment::open(&fixture.root, SITE, &fixture.writer)?;
    // A synthetic empty report retains metadata without performing network discovery.
    let retained = retain_discovery_sweep(
        &mut deployment,
        &[enrollment],
        &DiscoverReport::default(),
        1_000,
        &fixture.writer,
    )?;
    Ok(retained
        .first()
        .ok_or("retained liveness fixture")?
        .record
        .digest())
}

fn object(root: &Path, digest: ContentDigest) -> PathBuf {
    root.join("objects")
        .join(LOCAL_SPOOL_DIR)
        .join(SPOOL_OBJECTS_DIR)
        .join(hex(digest))
}
fn hex(digest: ContentDigest) -> String {
    digest
        .bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn files(root: &Path) -> Test<BTreeMap<PathBuf, (bool, Vec<u8>)>> {
    fn visit(
        root: &Path,
        path: &Path,
        out: &mut BTreeMap<PathBuf, (bool, Vec<u8>)>,
    ) -> Test {
        out.insert(path.strip_prefix(root)?.to_path_buf(), (true, Vec::new()));
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                visit(root, &path, out)?;
            } else {
                assert!(entry.file_type()?.is_file(), "unexpected special fixture entry");
                out.insert(path.strip_prefix(root)?.to_path_buf(), (false, fs::read(path)?));
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out)?;
    Ok(out)
}

#[test]
fn compares_complete_native_fields_and_same_digest_edge_attributes_without_media() -> Test {
    let fixture = Fixture::new("complete")?;
    // A metadata query must not open source or model children, or run the global spool doctor.
    for digest in [
        ContentDigest::sha256(SOURCE),
        fixture.from.model_receipts[0],
        fixture.to.model_receipts[0],
    ] {
        fs::remove_file(object(&fixture.root, digest))?;
    }
    let before = files(&fixture.root)?;
    let request = fixture.request()?;
    let limits = EventChangesLimits::default();
    let cx = context(&fixture.root, limits, false)?;
    let answer =
        explain_event_changes_in_deployment(&fixture.root, &request, limits, &cx, &|| false)?;
    assert_eq!(answer.report.from(), &fixture.from);
    assert_eq!(answer.report.to(), &fixture.to);
    assert_eq!(answer.report.from_publication_root(), fixture.roots[0]);
    assert_eq!(answer.report.to_publication_root(), fixture.roots[1]);
    assert_eq!(answer.report.from_commit_sequence(), 1);
    assert_eq!(answer.report.to_commit_sequence(), 2);
    assert_eq!(
        answer
            .report
            .changes()
            .iter()
            .map(|row| row.field())
            .collect::<Vec<_>>(),
        [
            "decisionPath",
            "evidence",
            "kind",
            "modelReceipts",
            "probability",
            "revision",
            "state",
            "supersedes",
            "timeInterval",
            "trackIds",
            "uncertaintyReason",
            "zoneIds"
        ]
    );
    let edges = answer
        .report
        .changes()
        .iter()
        .find(|row| row.field() == "evidence")
        .ok_or("evidence change")?;
    let same = ContentDigest::sha256(SOURCE).to_text();
    assert!(edges.before_json().contains(&same) && edges.after_json().contains(&same));
    for changed in [
        "\"class\":\"derived\"",
        "\"failureDomain\":\"sensor:new\"",
        "\"supports\":true",
        "\"relation\":\"supports\"",
        &fixture.to.evidence[0]
            .capsule_digest
            .ok_or("capsule")?
            .to_text(),
        &fixture.to.evidence[0]
            .identity_digest
            .ok_or("identity")?
            .to_text(),
    ] {
        assert!(
            edges.after_json().contains(changed),
            "complete changed edge field {changed}"
        );
    }
    assert!(
        !edges
            .after_json()
            .contains(&fixture.from.evidence[1].digest.to_text())
    );
    assert!(
        edges
            .after_json()
            .contains(&fixture.to.evidence[1].digest.to_text())
    );
    let times = answer
        .report
        .changes()
        .iter()
        .find(|row| row.field() == "timeInterval")
        .ok_or("time change")?;
    assert!(times.before_json().contains(&NS.to_string()));
    assert!(times.after_json().contains(&(NS + 1).to_string()));
    assert!(
        answer
            .report
            .to_json()
            .contains(&format!("\"schema\":\"{EVENT_CHANGES_SCHEMA}\""))
    );
    assert!(
        answer
            .report
            .to_json()
            .contains(&fixture.from.to_canonical_json())
    );
    assert!(
        answer
            .report
            .to_json()
            .contains(&fixture.to.to_canonical_json())
    );
    assert!(
        !answer
            .report
            .to_json()
            .contains(std::str::from_utf8(SOURCE)?)
    );
    assert_eq!(answer.receipt.question(), ExplainQuestion::WhatChanged);
    assert_eq!(answer.receipt.subject(), fixture.to.revision_digest());
    assert_eq!(answer.comparison_digest, answer.report.digest());
    for proof in [
        fixture.from.revision_digest(),
        fixture.to.revision_digest(),
        fixture.roots[0],
        fixture.roots[1],
        answer.comparison_digest,
    ] {
        assert!(answer.receipt.evidence_subgraph().contains(&proof));
    }
    // The existing Why compiler and every protected latest cell/world remain unchanged.
    assert_eq!(answer.explanation.receipt.question(), ExplainQuestion::Why);
    let ordinary = orient_deployment(
        &answer.snapshot,
        &OrientRequest {
            view: AgentView::Brief,
            principal: request.principal.clone(),
            budget_tokens: Some(1600),
        },
        &limits.read.snapshot,
    )?;
    let why = explain_event(&answer.snapshot, &ordinary, &request.event_id)?
        .ok_or("ordinary explanation")?;
    assert_eq!(answer.explanation.receipt, why.receipt);
    assert_eq!(answer.explanation.cells, why.cells);
    assert_eq!(answer.explanation.worlds, why.worlds);
    assert_eq!(answer.explanation.residual_ids, why.residual_ids);
    assert_eq!(answer.explanation.warnings, why.warnings);
    assert_eq!(answer.explanation.would_change, why.would_change);
    assert_eq!(answer.read_usage.read_bytes, answer.snapshot.bytes_read);
    assert_eq!(
        answer.read_usage.read_objects,
        answer.orientation.consumed.storage_operations
    );
    assert_eq!(files(&fixture.root)?, before);
    let again =
        explain_event_changes_in_deployment(&fixture.root, &request, limits, &cx, &|| false)?;
    assert_eq!(answer.report, again.report);
    assert_eq!(answer.receipt, again.receipt);
    assert_eq!(answer.request_digest, again.request_digest);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn requires_same_lineage_exact_current_head_and_immediate_predecessor() -> Test {
    let fixture = Fixture::new("adjacency")?;
    let mut request = fixture.request()?;
    let limits = EventChangesLimits::default();
    let cx = context(&fixture.root, limits, false)?;
    let prior =
        explain_event_changes_in_deployment(&fixture.root, &request, limits, &cx, &|| false)?;
    request.from_revision_digest = ContentDigest::sha256(b"another event revision");
    let error =
        explain_event_changes_in_deployment(&fixture.root, &request, limits, &cx, &|| false)
            .err()
            .ok_or("foreign predecessor refusal")?;
    assert!(matches!(error.kind, EventChangesErrorKind::NonAdjacent));
    assert!(error.observation.is_some());
    request = fixture.request()?;
    let third = fixture.third()?;
    let error =
        explain_event_changes_in_deployment(&fixture.root, &request, limits, &cx, &|| false)
            .err()
            .ok_or("stale target refusal")?;
    assert!(matches!(error.kind, EventChangesErrorKind::RevisionChanged));
    request.to_revision_digest = third.revision_digest();
    let error =
        explain_event_changes_in_deployment(&fixture.root, &request, limits, &cx, &|| false)
            .err()
            .ok_or("skipped revision refusal")?;
    assert!(matches!(error.kind, EventChangesErrorKind::NonAdjacent));
    request.from_revision_digest = fixture.to.revision_digest();
    request.expected_anchor = Some(AnchorToken::parse(&prior.anchor_token).ok_or("anchor")?);
    let error =
        explain_event_changes_in_deployment(&fixture.root, &request, limits, &cx, &|| false)
            .err()
            .ok_or("old authority refusal")?;
    assert!(matches!(error.kind, EventChangesErrorKind::AnchorChanged));
    request.expected_anchor = None;
    let next =
        explain_event_changes_in_deployment(&fixture.root, &request, limits, &cx, &|| false)?;
    assert_eq!(next.report.from(), &fixture.to);
    assert_eq!(next.report.to(), &third);
    request.event_id = EventId::parse("event:unpublished")?;
    let error =
        explain_event_changes_in_deployment(&fixture.root, &request, limits, &cx, &|| false)
            .err()
            .ok_or("unknown event refusal")?;
    assert!(matches!(error.kind, EventChangesErrorKind::UnknownEvent));
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn finish_refuses_changed_predecessor_payload_publication_and_authority() -> Test {
    for mutation in ["predecessor", "manifest", "head", "tombstone"] {
        let fixture = Fixture::new(mutation)?;
        let request = fixture.request()?;
        let limits = EventChangesLimits::default();
        let cx = context(&fixture.root, limits, false)?;
        let cancelled = || false;
        let prepared =
            prepare_event_changes_in_deployment(&fixture.root, &request, limits, &cx, &cancelled)?;
        assert_eq!(prepared.answer().report.from(), &fixture.from);
        match mutation {
            "predecessor" => fs::write(
                object(&fixture.root, fixture.payloads[0]),
                b"corrupted after full projection preparation",
            )?,
            "manifest" => fs::write(
                object(&fixture.root, fixture.roots[0]),
                b"changed predecessor publication",
            )?,
            "head" => {
                fixture.third()?;
            }
            "tombstone" => {
                let path = fixture
                    .root
                    .join("objects")
                    .join(LOCAL_TOMBSTONES_DIR)
                    .join(format!(
                        "{}{}",
                        fixture.payloads[0].to_text().replacen(':', "-", 1),
                        TOMBSTONE_RECORD_SUFFIX
                    ));
                fs::write(path, b"indeterminate tombstone must refuse")?;
            }
            _ => unreachable!(),
        }
        let before_finish = files(&fixture.root)?;
        let error = prepared
            .finish()
            .err()
            .ok_or("changed custody must withhold answer")?;
        assert!(matches!(error.kind, EventChangesErrorKind::Source(_)));
        assert!(error.observation.is_some());
        assert_eq!(files(&fixture.root)?, before_finish);
        cx.drain_and_finalize();
    }
    Ok(())
}

#[test]
fn cancellation_and_exact_admission_budgets_cover_finish_without_refills() -> Test {
    let fixture = Fixture::new("budgets")?;
    assert!(fs::read(fixture.root.join(RELATIVE_PATH_EFFECTS))?.is_empty());
    let before = files(&fixture.root)?;
    let request = fixture.request()?;
    let limits = EventChangesLimits::default();
    let cx = context(&fixture.root, limits, false)?;
    let measured =
        explain_event_changes_in_deployment(&fixture.root, &request, limits, &cx, &|| false)?;
    let mut exact = limits;
    // Final authority verification probes the empty effect journal after consuming the last
    // payload byte. That probe still needs positive byte credit and one read attempt; its
    // unused byte credit is not charged as payload or replenished between prepare and finish.
    exact.read.max_read_bytes = usize::try_from(measured.read_usage.read_bytes)?
        .checked_add(1)
        .ok_or("admission credit overflow")?;
    exact.read.max_read_objects = usize::try_from(measured.read_usage.read_objects)?;
    let exact_cx = context(&fixture.root, exact, false)?;
    let prepared =
        prepare_event_changes_in_deployment(&fixture.root, &request, exact, &exact_cx, &|| false)?;
    assert!(prepared.answer().read_usage.read_bytes < measured.read_usage.read_bytes);
    assert!(prepared.answer().read_usage.read_objects < measured.read_usage.read_objects);
    let answer = prepared.finish()?;
    assert_eq!(answer.report, measured.report);
    assert_eq!(answer.read_usage, measured.read_usage);
    assert_eq!(
        u64::try_from(exact.read.max_read_bytes)? - answer.read_usage.read_bytes,
        1
    );
    assert_eq!(files(&fixture.root)?, before);
    for bytes in [true, false] {
        let mut narrow = exact;
        if bytes {
            narrow.read.max_read_bytes -= 1;
        } else {
            narrow.read.max_read_objects -= 1;
        }
        let bounded = context(&fixture.root, narrow, false)?;
        let prepared = prepare_event_changes_in_deployment(
            &fixture.root,
            &request,
            narrow,
            &bounded,
            &|| false,
        )?;
        let error = prepared
            .finish()
            .err()
            .ok_or("the final empty-journal probe must stay within the original allowance")?;
        assert!(matches!(error.kind, EventChangesErrorKind::Source(_)));
        let observed = error.observation.ok_or("observed bounded refusal")?;
        assert_eq!(
            observed.read_usage.read_bytes,
            measured.read_usage.read_bytes
        );
        assert_eq!(
            observed.read_usage.read_objects + 1,
            measured.read_usage.read_objects
        );
        assert!(observed.read_usage.read_bytes <= u64::try_from(narrow.read.max_read_bytes)?);
        assert!(observed.read_usage.read_objects <= u64::try_from(narrow.read.max_read_objects)?);
        assert_eq!(files(&fixture.root)?, before);
        bounded.drain_and_finalize();
    }
    let cancelled = AtomicBool::new(false);
    let guard = || cancelled.load(Ordering::SeqCst);
    let prepared =
        prepare_event_changes_in_deployment(&fixture.root, &request, limits, &cx, &guard)?;
    cancelled.store(true, Ordering::SeqCst);
    assert!(prepared.finish().is_err());
    assert_eq!(files(&fixture.root)?, before);
    exact_cx.drain_and_finalize();
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn malformed_chain_and_unadmitted_requests_return_no_comparison() -> Test {
    // Individual revision metadata remains valid, but this terminal jump is not a legal chain.
    let fixture = Fixture::modified("invalid-chain", |to| to.state = EventState::Resolved)?;
    assert!(fixture.to.verify().is_ok());
    let request = fixture.request()?;
    let limits = EventChangesLimits::default();
    let cx = context(&fixture.root, limits, false)?;
    let error =
        explain_event_changes_in_deployment(&fixture.root, &request, limits, &cx, &|| false)
            .err()
            .ok_or("invalid chain refusal")?;
    assert!(matches!(error.kind, EventChangesErrorKind::InvalidRecord));
    let mut same = request.clone();
    same.from_revision_digest = same.to_revision_digest;
    let error = explain_event_changes_in_deployment(&fixture.root, &same, limits, &cx, &|| false)
        .err()
        .ok_or("equal endpoints refusal")?;
    assert!(matches!(error.kind, EventChangesErrorKind::InvalidRequest));
    assert!(error.observation.is_none());
    let mut other = request.clone();
    other.principal = PrincipalId::parse("principal:other")?;
    let error = explain_event_changes_in_deployment(&fixture.root, &other, limits, &cx, &|| false)
        .err()
        .ok_or("principal refusal")?;
    assert!(matches!(error.kind, EventChangesErrorKind::Unauthorized));
    assert!(error.observation.is_none());
    let missing = fixture._directory.0.join("must-not-be-created");
    assert!(
        explain_event_changes_in_deployment(&missing, &request, limits, &cx, &|| false).is_err()
    );
    assert!(!missing.exists());
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn canonical_signed_zero_is_not_an_invented_probability_change() -> Test {
    let fixture = Fixture::modified("canonical-zero", |to| {
        to.probability = ProbabilityInterval {
            lower: -0.0,
            upper: 1.0,
            calibration_generation: None,
        };
    })?;
    let request = fixture.request()?;
    let limits = EventChangesLimits::default();
    let cx = context(&fixture.root, limits, false)?;
    let answer =
        explain_event_changes_in_deployment(&fixture.root, &request, limits, &cx, &|| false)?;
    assert!(
        answer
            .report
            .changes()
            .iter()
            .all(|row| row.field() != "probability")
    );
    // Event canonical bytes normalize both zeros. The actual calibration/interval changes in
    // the complete fixture above remain visible rather than being parsed through a JSON f64.
    let mut canonical = fixture.to.clone();
    canonical.probability.lower = 0.0;
    assert_eq!(canonical.revision_digest(), fixture.to.revision_digest());
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn complete_json_bound_refuses_valid_large_native_metadata_without_a_prefix() -> Test {
    let fixture = Fixture::modified("whole-output-bound", |to| {
        // Native bounds permit these exact strings. Their JSON escapes consume real output
        // bytes, so limiting only event count or canonical binary bytes would be insufficient.
        to.evidence = (0..fss_core::event::MAX_EVIDENCE_COUNT)
            .map(|index| EventEvidence {
                digest: ContentDigest::sha256(
                    format!("bounded-unexpanded-evidence:{index}").as_bytes(),
                ),
                class: EvidenceClass::Assertion,
                failure_domain: "\u{1}".repeat(fss_core::event::MAX_FAILURE_DOMAIN_LEN),
                supports: false,
                relation: EvidenceEdgeRelation::DerivedFrom,
                capsule_digest: Some(ContentDigest::sha256(b"bounded capsule declaration")),
                identity_digest: Some(ContentDigest::sha256(b"bounded identity declaration")),
            })
            .collect();
    })?;
    fixture.to.verify()?;
    let before = files(&fixture.root)?;
    let request = fixture.request()?;
    let limits = EventChangesLimits::default();
    let cx = context(&fixture.root, limits, false)?;
    let error =
        explain_event_changes_in_deployment(&fixture.root, &request, limits, &cx, &|| false)
            .err()
            .ok_or("whole projection must be refused")?;
    assert!(matches!(error.kind, EventChangesErrorKind::BudgetExceeded));
    assert!(error.observation.is_some());
    assert_eq!(files(&fixture.root)?, before);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn shared_lineage_verifier_refuses_empty_or_reordered_inputs_and_revalidates_metadata() -> Test {
    let fixture = Fixture::new("shared-lineage-verifier")?;
    for digest in [
        ContentDigest::sha256(SOURCE),
        fixture.from.model_receipts[0],
        fixture.to.model_receipts[0],
    ] {
        fs::remove_file(object(&fixture.root, digest))?;
    }
    let before = files(&fixture.root)?;
    let limits = EventChangesLimits::default();
    let cx = context(&fixture.root, limits, false)?;
    let owner = ImmutableRetainedSource::open(&fixture.root, limits.read, &cx)?;
    let opening_usage = owner.usage();
    assert!(
        verify_event_lineage(&owner, &[], limits.read.snapshot.max_object_bytes).is_err()
    );
    assert!(
        verify_event_lineage(
            &owner,
            &[fixture.to.clone(), fixture.from.clone()],
            limits.read.snapshot.max_object_bytes,
        )
        .is_err()
    );
    assert_eq!(owner.usage(), opening_usage, "invalid chains spend no payload I/O");

    let publications = verify_event_lineage(
        &owner,
        &[fixture.from.clone(), fixture.to.clone()],
        limits.read.snapshot.max_object_bytes,
    )?;
    assert_eq!(publications, vec![(fixture.roots[0], 1), (fixture.roots[1], 2)]);
    assert!(owner.usage().read_objects > opening_usage.read_objects);
    owner.revalidate()?;
    assert_eq!(files(&fixture.root)?, before, "metadata verification is read only");

    // Selected metadata remains registered even though source and model children were absent.
    let path = object(&fixture.root, fixture.payloads[0]);
    let mut changed = fs::read(&path)?;
    changed.push(0);
    fs::write(&path, changed)?;
    let before_refusal = files(&fixture.root)?;
    assert!(owner.revalidate().is_err(), "late metadata changes invalidate the result");
    assert_eq!(files(&fixture.root)?, before_refusal);
    drop(owner);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn snapshot_metadata_revalidation_detects_changed_non_event_liveness_without_new_authority() -> Test {
    for remove in [false, true] {
        let fixture = Fixture::new(if remove { "missing-liveness" } else { "changed-liveness" })?;
        let digest = retain_liveness_metadata(&fixture)?;
        let before = files(&fixture.root)?;
        let limits = EventChangesLimits::default();
        let cx = context(&fixture.root, limits, false)?;
        let owner = ImmutableRetainedSource::open(&fixture.root, limits.read, &cx)?;
        assert_eq!(owner.snapshot().sensor_liveness.len(), 1);
        let opening_usage = owner.usage();
        owner.revalidate_snapshot_metadata()?;
        assert!(owner.usage().read_bytes > opening_usage.read_bytes);
        assert!(owner.usage().read_objects > opening_usage.read_objects);
        owner.revalidate()?;
        assert_eq!(files(&fixture.root)?, before);

        let path = object(&fixture.root, digest);
        if remove {
            fs::remove_file(&path)?;
        } else {
            fs::write(&path, b"changed retained liveness metadata")?;
        }
        let before_refusal = files(&fixture.root)?;
        assert!(
            owner.revalidate_snapshot_metadata().is_err(),
            "changed non-event context must not survive with unchanged ledger/effect heads"
        );
        assert!(
            owner.revalidate().is_err(),
            "a failed metadata reread poisons the original allowance"
        );
        assert_eq!(files(&fixture.root)?, before_refusal);
        drop(owner);
        cx.drain_and_finalize();
    }
    Ok(())
}

#[test]
fn finish_refuses_changed_non_event_liveness_after_complete_preparation() -> Test {
    for remove in [false, true] {
        let fixture = Fixture::new(if remove {
            "finish-missing-liveness"
        } else {
            "finish-corrupt-liveness"
        })?;
        let digest = retain_liveness_metadata(&fixture)?;
        let request = fixture.request()?;
        let limits = EventChangesLimits::default();
        let cx = context(&fixture.root, limits, false)?;
        let cancelled = || false;
        let before_prepare = files(&fixture.root)?;
        let prepared =
            prepare_event_changes_in_deployment(&fixture.root, &request, limits, &cx, &cancelled)?;
        assert_eq!(prepared.answer().snapshot.sensor_liveness.len(), 1);
        assert_eq!(prepared.answer().report.from(), &fixture.from);
        assert_eq!(prepared.answer().report.to(), &fixture.to);
        let preview_usage = prepared.answer().read_usage;
        let observed_anchor = prepared.answer().snapshot.anchor.clone();
        assert_eq!(files(&fixture.root)?, before_prepare, "prepare must be read only");

        // This is protected non-event context, outside the selected event publication
        // lineage. Neither the committed authority head nor the event revisions change.
        let path = object(&fixture.root, digest);
        if remove {
            fs::remove_file(&path)?;
        } else {
            fs::write(&path, b"liveness metadata changed after full comparison preparation")?;
        }
        let before_finish = files(&fixture.root)?;
        let error = prepared
            .finish()
            .err()
            .ok_or("late non-event metadata tampering must withhold the prepared answer")?;
        assert!(matches!(error.kind, EventChangesErrorKind::Source(_)));
        let observation = error.observation.ok_or("observed metadata refusal")?;
        assert_eq!(observation.anchor, observed_anchor);
        assert!(
            observation.read_usage.read_objects > preview_usage.read_objects,
            "the failed non-event reread must be charged to the original allowance"
        );
        assert!(observation.read_usage.read_bytes <= u64::try_from(limits.read.max_read_bytes)?);
        assert!(observation.read_usage.read_objects <= u64::try_from(limits.read.max_read_objects)?);
        assert_eq!(
            files(&fixture.root)?,
            before_finish,
            "finish must neither repair tampered metadata nor perform writer work"
        );
        cx.drain_and_finalize();
    }
    Ok(())
}
