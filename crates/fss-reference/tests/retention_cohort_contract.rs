#![forbid(unsafe_code)]
//! Real imported media, durable holds and graph-aware partial retention cleanup.
//! No camera, host clock, network effect or automatically released hold is involved.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, CapsuleId, CaptureInterval, ContentDigest, EventEvidence, EventId, EvidenceClass,
    EvidenceEdgeRelation, IdempotencyKey, ObligationId, OperationId, ProbabilityInterval, SensorId,
    StreamId, TimestampNs,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits};
use fss_publication::SlotName;
use fss_reference::deletion::holds::{
    CAP_HOLD_COMMIT, CAP_HOLD_PREPARE, HoldRequest, HoldState, commit_hold, preview_hold,
};
use fss_reference::deletion::retention::{
    RETENTION_BLOCKER_SELECTION_DOMAIN, RETENTION_BYTE_SELECTION_DOMAIN,
    RETENTION_SELECTION_DOMAIN, RetentionDisposition, RetentionRequest, STAGE_RETENTION_COHORT,
    STAGE_RETENTION_READ, commit_retention, plan_retention,
};
use fss_reference::deletion::{
    CommitOutcome, DELETION_CUT_POINTS, DeletionError, DeletionIndex, DeletionPlan, plan_deletion,
    plan_scope_deletion,
};
use fss_reference::ingest::{
    CaptureHint, FileFormatHint, FileIngestAdapter, FileIngestRequest, RetainedFileImport,
    RetainedReadLimits,
};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{
    DeliveryPlan, MockModelScript, MockModelSpec, MockSemanticLabel, PrepareAlertParams,
    ReferenceAlertPlan, ReferenceDeployment, ReferenceModelObservation, ReferencePolicyAction,
    ReplayCx, VirtualCameraSpec, evaluate_unknown_presence, execute_mock_model,
    run_reference_capture,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const SITE: &str = "site:retention-cohort";
const PRINCIPAL: &str = "principal:retention-cohort";
const SENSOR: &str = "sensor:cohort-camera";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> TestResult<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-retention-cohort-{label}-{}-{attempt}",
                std::process::id(),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("test directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    deployment: ReferenceDeployment,
    cx: ReplayCx,
    authority: ContextAuthority,
    directory: Directory,
}

#[derive(Clone, Copy)]
struct Import {
    identity: ContentDigest,
    source: ContentDigest,
}

fn interval(first: i128, last: i128) -> TestResult<CaptureInterval> {
    Ok(CaptureInterval::new(TimestampNs(first), TimestampNs(last))?)
}

fn request() -> TestResult<RetentionRequest> {
    Ok(RetentionRequest::new(
        SensorId::parse(SENSOR)?,
        100,
        interval(1000, 1010)?,
    )?)
}

fn snapshot(root: &Path) -> TestResult<BTreeMap<PathBuf, Vec<u8>>> {
    fn walk(root: &Path, at: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) -> TestResult {
        for entry in fs::read_dir(at)? {
            let path = entry?.path();
            if path.is_dir() {
                walk(root, &path, out)?;
            } else {
                out.insert(path.strip_prefix(root)?.to_path_buf(), fs::read(path)?);
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out)?;
    Ok(out)
}

impl Fixture {
    fn new(label: &str) -> TestResult<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:retention-cohort".to_owned(),
            operation_id: OperationId::parse("operation:retention-cohort")?,
            principal: PRINCIPAL.to_owned(),
            capabilities: [
                "ADP-REPLAY-001",
                "ADP-FILE-001",
                CAP_HOLD_PREPARE,
                CAP_HOLD_COMMIT,
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(64 * 1024 * 1024)
                .storage_operations(8192)
                .build()?,
            privacy_scope: "privacy:retention-cohort".to_owned(),
            retention_scope: "retention:explicit-owner-request".to_owned(),
            anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
            generation: 1,
        })?;
        let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
        let deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        Ok(Self {
            deployment,
            cx,
            authority,
            directory,
        })
    }

    fn ingest(&mut self, name: &str, gray: u8) -> TestResult<Import> {
        self.ingest_at(name, gray, SENSOR, Some(0))
    }

    fn ingest_at(
        &mut self,
        name: &str,
        gray: u8,
        sensor: &str,
        at: Option<i128>,
    ) -> TestResult<Import> {
        let path = self.directory.0.join(format!("{name}.mjpeg"));
        fs::write(
            &path,
            encode_jpeg(
                16,
                16,
                &[gray; 256],
                &JpegConfig {
                    quality: 90,
                    subsampling: Subsampling::Grayscale,
                    restart_interval: 0,
                    custom_markers: Vec::new(),
                },
            )?,
        )?;
        let mut input = FileIngestRequest::new(
            path,
            SensorId::parse(sensor)?,
            StreamId::parse(format!("stream:{name}"))?,
        )
        .with_receive_time(TimestampNs(2000))
        .with_format_hint(FileFormatHint::JpegStream);
        if let Some(at) = at {
            input = input.with_capture_hint(CaptureHint::new(TimestampNs(at), 0, 1.0)?);
        }
        let imported = FileIngestAdapter::ingest(input, &self.cx, &mut self.deployment)?;
        Ok(Import {
            identity: imported.import_identity,
            source: imported.input_sha256,
        })
    }

    fn hold(&mut self, id: &str, import: Import, state: HoldState) -> TestResult {
        let request = HoldRequest {
            hold_id: id.to_owned(),
            import_identity: import.identity,
            state,
            reason: "Explicit owner preservation decision".to_owned(),
        };
        let preview = preview_hold(&self.deployment, &request, &self.authority, &self.cx)?;
        commit_hold(
            &mut self.deployment,
            &request,
            preview.record.approval(),
            &self.authority,
            &self.cx,
        )?;
        Ok(())
    }

    fn readable(&self, import: Import) -> TestResult {
        RetainedFileImport::open(
            &self.deployment,
            import.identity,
            RetainedReadLimits::default(),
            &self.cx,
        )?;
        let bytes = self.deployment.publisher().spool().read(import.source)?;
        assert_eq!(ContentDigest::sha256(&bytes), import.source);
        Ok(())
    }

    fn source_bytes(&self, import: Import) -> TestResult<u64> {
        Ok(RetainedFileImport::open(
            &self.deployment,
            import.identity,
            RetainedReadLimits::default(),
            &self.cx,
        )?
        .manifest()
        .input_bytes)
    }

    fn fresh_cx(&self) -> TestResult<ReplayCx> {
        Ok(ReplayCx::from_context_authority(
            &self.authority,
            self.deployment.root().to_path_buf(),
        )?)
    }

    fn reopen(self) -> TestResult<Self> {
        let Self {
            deployment,
            cx,
            authority,
            directory,
        } = self;
        let root = deployment.root().to_path_buf();
        drop(deployment);
        drop(cx);
        let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
        let deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        Ok(Self {
            deployment,
            cx,
            authority,
            directory,
        })
    }

    /// Prepare a local synthetic alert dependency without dispatching anything.
    fn pending_alert(&mut self, dependency: ContentDigest) -> TestResult<ReferenceAlertPlan> {
        let mut objects = InMemoryObjectStore::new(ObjectLimits::new(2048, 32 * 1024 * 1024));
        let mut captures = DurableReferenceLedger::open(
            self.directory.0.join("observations.journal"),
            "site:cohort-observations",
            IncompleteTailPolicy::Reject,
        )?;
        let mut observations = Vec::new();
        for (lane, seed) in [("a", 111), ("b", 222)] {
            let spec = VirtualCameraSpec {
                capture_id: CapsuleId::parse(format!("capture:cohort:{lane}"))?,
                sensor_id: SensorId::parse(format!("sensor:cohort-observation:{lane}"))?,
                seed,
                packet_count: 2,
                packet_bytes: 32,
                start_ns: 10_000,
                period_ns: 1_000_000,
                uncertainty_ns: 100,
            };
            let capture = run_reference_capture(
                &spec,
                &DeliveryPlan::identity(spec.packet_count)?,
                &mut objects,
                &mut captures,
            )?;
            let model = MockModelSpec::new(
                format!("mock:cohort:{lane}:v1"),
                MockModelScript::Fixed {
                    label: MockSemanticLabel::PersonLike,
                    probability: ProbabilityInterval::new(0.99, 1.0)?,
                },
            )?;
            observations.push(ReferenceModelObservation::new(
                execute_mock_model(&model, &capture, &mut objects)?,
                format!("power:cohort:{lane}"),
                interval(10_000, 20_000)?,
            )?);
        }
        let mut decision =
            evaluate_unknown_presence(EventId::parse("event:cohort")?, observations)?;
        assert_eq!(decision.action, ReferencePolicyAction::PrepareAlert);
        decision.event.evidence.push(EventEvidence {
            digest: dependency,
            class: EvidenceClass::Assertion,
            failure_domain: "dependency:retained-recording".to_owned(),
            supports: false,
            relation: EvidenceEdgeRelation::RequiredBy,
            capsule_digest: None,
            identity_digest: None,
        });
        decision.event.validate()?;
        for digest in &decision.event.model_receipts {
            assert_eq!(
                self.deployment
                    .stage_payload(objects.read_verified(*digest)?)?,
                *digest
            );
        }
        let event = self.deployment.publish_event(&decision, &self.cx)?;
        let (journal, authority) = self.deployment.effects_and_ledger();
        Ok(journal.prepare_alert(PrepareAlertParams {
            decision: &decision,
            event_receipt: &event,
            authority,
            operation_id: OperationId::parse("operation:cohort-alert")?,
            idempotency_key: IdempotencyKey::parse("idempotency:cohort-alert")?,
            obligation_id: ObligationId::parse("obligation:cohort-alert")?,
            channel: "test-only-no-dispatch".to_owned(),
            now: TimestampNs(3_000_000_000),
        })?)
    }
}

#[test]
fn unblocked_age_cohort_keeps_v1_and_preserves_unknown_and_recent_recordings() -> TestResult {
    let mut f = Fixture::new("age")?;
    let a = f.ingest("a", 20)?;
    let b = f.ingest("b", 40)?;
    let recent = f.ingest_at("recent", 60, SENSOR, Some(950))?;
    let unknown = f.ingest_at("unknown", 80, SENSOR, None)?;
    let before = snapshot(f.deployment.root())?;
    let preview = plan_retention(&f.deployment, &request()?, &f.cx)?;
    assert_eq!(snapshot(f.deployment.root())?, before);
    assert_eq!(
        preview.assessment.selection.domain(),
        RETENTION_SELECTION_DOMAIN
    );
    assert_eq!(preview.assessment.closure_evaluations, 1);
    assert_eq!(preview.assessment.held_closures, 0);
    assert!(preview.assessment.closure_scanned_objects > 0);
    let states: BTreeMap<_, _> = preview
        .assessment
        .selection
        .candidates()
        .iter()
        .map(|c| (c.import_identity(), c.disposition()))
        .collect();
    assert_eq!(states[&recent.identity], RetentionDisposition::NotDue);
    assert_eq!(
        states[&unknown.identity],
        RetentionDisposition::CaptureTimeUnknown
    );
    let plan = preview.deletion.ok_or("expected unblocked deletion")?;
    assert!(plan.blockers.is_empty());
    assert_eq!(
        plan.imports.iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([a.identity, b.identity])
    );
    assert_eq!(
        DeletionPlan::decode(&plan.canonical_bytes()?, plan.digest()?)?,
        plan
    );
    assert_eq!(
        plan_scope_deletion(&f.deployment, &plan.scope, &f.cx)?,
        plan
    );
    commit_retention(
        &mut f.deployment,
        &request()?,
        plan.digest()?,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &f.cx,
    )?;
    f.readable(recent)?;
    f.readable(unknown)?;
    Ok(())
}

#[test]
fn held_expired_import_is_explicit_while_independent_cleanup_commits_and_retries() -> TestResult {
    let mut f = Fixture::new("hold")?;
    let held = f.ingest("held", 40)?;
    let free = f.ingest("free", 80)?;
    f.hold("incident", held, HoldState::Held)?;
    let before = snapshot(f.deployment.root())?;
    let preview = plan_retention(&f.deployment, &request()?, &f.cx)?;
    assert_eq!(snapshot(f.deployment.root())?, before);
    assert_eq!(
        preview.assessment.selection.domain(),
        RETENTION_BLOCKER_SELECTION_DOMAIN
    );
    assert_eq!(preview.assessment.held_closures, 1);
    assert_eq!(preview.assessment.closure_evaluations, 4);
    let excluded = preview
        .assessment
        .selection
        .candidates()
        .iter()
        .find(|c| c.import_identity() == held.identity)
        .ok_or("missing held candidate")?;
    assert_eq!(excluded.disposition(), RetentionDisposition::ClosureBlocked);
    assert!(excluded.capture_end().is_some());
    assert!(excluded.closure_witness().is_some());
    assert!(
        excluded
            .blockers()
            .iter()
            .any(|f| f.kind == "evidence_hold" && f.subject == "incident")
    );
    let plan = preview
        .deletion
        .ok_or("independent import should remain selectable")?;
    assert_eq!(plan.imports, vec![free.identity]);
    assert!(plan.blockers.is_empty());
    assert_eq!(
        DeletionPlan::decode(&plan.canonical_bytes()?, plan.digest()?)?,
        plan
    );
    assert_eq!(
        plan_scope_deletion(&f.deployment, &plan.scope, &f.cx)?,
        plan
    );
    let digest = plan.digest()?;
    let approval = plan.approval_digest(PRINCIPAL)?;
    let receipt = commit_retention(
        &mut f.deployment,
        &request()?,
        digest,
        approval,
        PRINCIPAL,
        &f.cx,
    )?;
    assert_eq!(receipt.outcome, CommitOutcome::Completed);
    f.readable(held)?;
    assert!(
        RetainedFileImport::open(
            &f.deployment,
            free.identity,
            RetainedReadLimits::default(),
            &f.cx
        )
        .is_err()
    );
    let head = f.deployment.current_anchor().clone();
    let again = commit_retention(
        &mut f.deployment,
        &request()?,
        digest,
        approval,
        PRINCIPAL,
        &f.cx,
    )?;
    assert_eq!(again.outcome, CommitOutcome::AlreadyComplete);
    assert_eq!(again.completion_digest, receipt.completion_digest);
    assert_eq!(f.deployment.current_anchor(), &head);
    Ok(())
}

#[test]
fn held_derivative_outside_sensor_protects_its_neighbour_without_stopping_other_cleanup()
-> TestResult {
    let mut f = Fixture::new("shared-derivative")?;
    let held = f.ingest_at("held", 20, "sensor:other-camera", Some(0))?;
    let neighbour = f.ingest("neighbour", 80)?;
    let free = f.ingest("independent", 120)?;
    f.hold("incident", held, HoldState::Held)?;
    let mut shared = b"derived from both held and neighbouring imports".to_vec();
    shared.extend(held.identity.bytes());
    shared.extend(neighbour.identity.bytes());
    let slot = SlotName::parse("cohort-shared")?;
    let staged = f
        .deployment
        .stage_and_publish(&slot, &[shared.as_slice()], &f.cx)?;
    f.deployment
        .publish_and_commit(&slot, &staged.manifest, interval(0, 0)?, &f.cx)?;
    let preview = plan_retention(&f.deployment, &request()?, &f.cx)?;
    assert_eq!(preview.assessment.outside_sensor, 1);
    let excluded = preview
        .assessment
        .selection
        .candidates()
        .iter()
        .find(|c| c.import_identity() == neighbour.identity)
        .ok_or("missing neighbouring import")?;
    assert_eq!(excluded.disposition(), RetentionDisposition::ClosureBlocked);
    assert!(
        excluded
            .blockers()
            .iter()
            .any(|f| f.kind == "evidence_hold")
    );
    let plan = preview.deletion.ok_or("expected independent cleanup")?;
    assert_eq!(plan.imports, vec![free.identity]);
    commit_retention(
        &mut f.deployment,
        &request()?,
        plan.digest()?,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &f.cx,
    )?;
    f.readable(held)?;
    f.readable(neighbour)?;
    assert_eq!(
        f.deployment
            .publisher()
            .spool()
            .read(ContentDigest::sha256(&shared))?,
        shared
    );
    Ok(())
}

#[test]
fn shared_source_bytes_can_remain_held_while_an_independent_import_is_removed() -> TestResult {
    let mut f = Fixture::new("shared-source")?;
    let held = f.ingest_at("held", 40, "sensor:other-camera", Some(0))?;
    let free = f.ingest("free", 40)?;
    assert_eq!(held.source, free.source);
    f.hold("incident", held, HoldState::Held)?;
    let preview = plan_retention(&f.deployment, &request()?, &f.cx)?;
    assert_eq!(
        preview.assessment.selection.domain(),
        RETENTION_SELECTION_DOMAIN
    );
    let plan = preview
        .deletion
        .ok_or("shared source can stay in retained custody")?;
    assert_eq!(plan.imports, vec![free.identity]);
    assert!(!plan.deletable.iter().any(|o| o.digest == held.source));
    commit_retention(
        &mut f.deployment,
        &request()?,
        plan.digest()?,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &f.cx,
    )?;
    f.readable(held)
}

#[test]
fn every_proposed_union_is_checked_when_individually_safe_imports_share_effect_evidence()
-> TestResult {
    let mut f = Fixture::new("union-effect")?;
    let a = f.ingest("a", 40)?;
    let b = f.ingest("b", 40)?;
    let free = f.ingest("independent", 120)?;
    assert_eq!(a.source, b.source);
    let alert = f.pending_alert(a.source)?;
    for import in [a, b] {
        assert!(
            plan_deletion(&f.deployment, import.identity, &f.cx)?
                .blockers
                .is_empty()
        );
    }
    let preview = plan_retention(&f.deployment, &request()?, &f.cx)?;
    let kept = a.identity.max(b.identity);
    let selected = a.identity.min(b.identity);
    let excluded = preview
        .assessment
        .selection
        .candidates()
        .iter()
        .find(|c| c.import_identity() == kept)
        .ok_or("missing retained shared-source import")?;
    assert_eq!(excluded.disposition(), RetentionDisposition::ClosureBlocked);
    assert!(
        excluded
            .blockers()
            .iter()
            .any(|f| f.kind == "open_effect" && f.subject == alert.intent.operation_id.as_str())
    );
    let plan = preview.deletion.ok_or("safe partial cohort")?;
    assert!(plan.blockers.is_empty());
    assert_eq!(
        plan.imports.iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([selected, free.identity])
    );
    assert!(!plan.deletable.iter().any(|o| o.digest == a.source));
    commit_retention(
        &mut f.deployment,
        &request()?,
        plan.digest()?,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &f.cx,
    )?;
    f.readable(Import {
        identity: kept,
        source: a.source,
    })?;
    assert!(
        !f.deployment
            .effects()
            .operation(&alert.intent.operation_id)
            .ok_or("pending effect disappeared")?
            .state
            .is_terminal()
    );
    Ok(())
}

#[test]
fn changed_holds_and_later_imports_invalidate_prior_approvals_without_writing() -> TestResult {
    let mut f = Fixture::new("stale")?;
    let held = f.ingest("held", 40)?;
    let free = f.ingest("free", 80)?;
    f.hold("incident", held, HoldState::Held)?;
    let plan = plan_retention(&f.deployment, &request()?, &f.cx)?
        .deletion
        .ok_or("plan")?;
    f.hold("new-hold", free, HoldState::Held)?;
    let all_blocked = plan_retention(&f.deployment, &request()?, &f.cx)?;
    assert!(all_blocked.deletion.is_none());
    assert!(all_blocked.assessment.selection.imports().is_empty());
    assert!(
        all_blocked
            .assessment
            .selection
            .candidates()
            .iter()
            .all(|c| c.disposition() == RetentionDisposition::ClosureBlocked)
    );
    let before = snapshot(f.deployment.root())?;
    assert!(matches!(
        commit_retention(
            &mut f.deployment,
            &request()?,
            plan.digest()?,
            plan.approval_digest(PRINCIPAL)?,
            PRINCIPAL,
            &f.cx
        ),
        Err(DeletionError::StalePlan(_))
    ));
    assert_eq!(snapshot(f.deployment.root())?, before);
    assert!(plan_scope_deletion(&f.deployment, &plan.scope, &f.cx).is_err());
    f.hold("incident", held, HoldState::Released)?;
    f.hold("new-hold", free, HoldState::Released)?;
    let current = plan_retention(&f.deployment, &request()?, &f.cx)?
        .deletion
        .ok_or("released cohort")?;
    assert_eq!(current.imports.len(), 2);
    let _ = f.ingest("later", 120)?;
    let before = snapshot(f.deployment.root())?;
    assert!(matches!(
        commit_retention(
            &mut f.deployment,
            &request()?,
            current.digest()?,
            current.approval_digest(PRINCIPAL)?,
            PRINCIPAL,
            &f.cx
        ),
        Err(DeletionError::StalePlan(_))
    ));
    assert_eq!(snapshot(f.deployment.root())?, before);
    f.readable(held)?;
    f.readable(free)
}

#[test]
fn cancelled_selection_never_writes_or_returns_a_partial_cohort() -> TestResult {
    for budget in [None, Some(0)] {
        for stage in [STAGE_RETENTION_READ, STAGE_RETENTION_COHORT] {
            let mut request = request()?;
            if let Some(budget) = budget {
                request = request.with_source_byte_budget(budget);
            }
            let mut f = Fixture::new("selection-cancel")?;
            let held = f.ingest("held", 40)?;
            let free = f.ingest("free", 80)?;
            f.hold("incident", held, HoldState::Held)?;
            let before = snapshot(f.deployment.root())?;
            f.cx.set_cancel_at_checkpoint(stage);
            assert!(matches!(plan_retention(&f.deployment, &request, &f.cx),
                Err(DeletionError::Cancelled { stage: hit }) if hit == stage));
            assert_eq!(snapshot(f.deployment.root())?, before);
            f.cx = f.fresh_cx()?;
            let plan = plan_retention(&f.deployment, &request, &f.cx)?
                .deletion
                .ok_or("retry plan")?;
            assert_eq!(plan.imports, vec![free.identity]);
        }
    }
    Ok(())
}

#[test]
fn every_cleanup_cut_preserves_holds_and_resumes_the_exact_bound_cohort_after_reopen() -> TestResult
{
    for stage in DELETION_CUT_POINTS {
        let mut f = Fixture::new("commit-cancel")?;
        let held = f.ingest("held", 40)?;
        let free = f.ingest("free", 80)?;
        f.hold("incident", held, HoldState::Held)?;
        let plan = plan_retention(&f.deployment, &request()?, &f.cx)?
            .deletion
            .ok_or("plan")?;
        let digest = plan.digest()?;
        let approval = plan.approval_digest(PRINCIPAL)?;
        f.cx.set_cancel_at_checkpoint(stage);
        assert!(
            matches!(commit_retention(&mut f.deployment, &request()?, digest,
            approval, PRINCIPAL, &f.cx), Err(DeletionError::Cancelled { stage: hit }) if hit == *stage)
        );
        let durable = DeletionIndex::read(&f.deployment)?.plan(digest).is_some();
        let mut f = f.reopen()?;
        let wrong = RetentionRequest::new(SensorId::parse(SENSOR)?, 101, interval(1000, 1010)?)?;
        assert!(matches!(
            commit_retention(
                &mut f.deployment,
                &wrong,
                digest,
                approval,
                PRINCIPAL,
                &f.cx
            ),
            Err(DeletionError::StalePlan(_))
        ));
        let receipt = commit_retention(
            &mut f.deployment,
            &request()?,
            digest,
            approval,
            PRINCIPAL,
            &f.cx,
        )?;
        assert_eq!(
            receipt.outcome,
            if durable {
                CommitOutcome::Resumed
            } else {
                CommitOutcome::Completed
            }
        );
        assert_eq!(receipt.plan, plan);
        f.readable(held)?;
        assert!(
            RetainedFileImport::open(
                &f.deployment,
                free.identity,
                RetainedReadLimits::default(),
                &f.cx
            )
            .is_err()
        );
        let again = commit_retention(
            &mut f.deployment,
            &request()?,
            digest,
            approval,
            PRINCIPAL,
            &f.cx,
        )?;
        assert_eq!(again.outcome, CommitOutcome::AlreadyComplete);
        assert_eq!(again.completion_digest, receipt.completion_digest);
    }
    Ok(())
}

#[test]
fn identical_evidence_has_identical_selection_and_plan_across_storage_roots() -> TestResult {
    fn prepare(label: &str) -> TestResult<(ContentDigest, ContentDigest)> {
        let mut f = Fixture::new(label)?;
        let held = f.ingest("held", 40)?;
        let _ = f.ingest("free", 80)?;
        f.hold("incident", held, HoldState::Held)?;
        let preview = plan_retention(&f.deployment, &request()?, &f.cx)?;
        Ok((
            preview.assessment.selection.digest()?,
            preview.deletion.ok_or("plan")?.digest()?,
        ))
    }
    assert_eq!(prepare("root-a")?, prepare("root-b")?);
    Ok(())
}

#[test]
fn byte_budget_selects_oldest_then_stops_and_binds_the_exact_target() -> TestResult {
    let mut f = Fixture::new("budget-oldest")?;
    let newest = f.ingest_at("newest", 120, SENSOR, Some(300))?;
    let oldest = f.ingest_at("oldest", 40, SENSOR, Some(-200))?;
    let middle = f.ingest_at("middle", 80, SENSOR, Some(100))?;
    let oldest_bytes = f.source_bytes(oldest)?;
    let target = f.source_bytes(middle)? + f.source_bytes(newest)?;
    let request = request()?.with_source_byte_budget(target);
    let before = snapshot(f.deployment.root())?;
    let preview = plan_retention(&f.deployment, &request, &f.cx)?;
    assert_eq!(snapshot(f.deployment.root())?, before);
    assert_eq!(
        preview.assessment.selection.domain(),
        RETENTION_BYTE_SELECTION_DOMAIN
    );
    assert_eq!(preview.assessment.closure_evaluations, 2);
    let accounting = preview
        .assessment
        .selection
        .byte_accounting()
        .ok_or("accounting")?;
    assert_eq!(accounting.max_retained_source_bytes, target);
    assert_eq!(accounting.before_source_bytes, target + oldest_bytes);
    assert_eq!(accounting.selected_source_bytes, oldest_bytes);
    assert_eq!(accounting.projected_remaining_source_bytes, target);
    assert_eq!(accounting.unmet_source_bytes, 0);
    for candidate in preview.assessment.selection.candidates() {
        assert!(candidate.source_digest().is_some());
        assert!(candidate.source_bytes().is_some());
        assert_eq!(
            candidate.disposition(),
            if candidate.import_identity() == oldest.identity {
                RetentionDisposition::Eligible
            } else {
                RetentionDisposition::BudgetRetained
            }
        );
    }
    let plan = preview.deletion.ok_or("oldest deletion")?;
    assert_eq!(plan.imports, vec![oldest.identity]);
    assert!(plan.blockers.is_empty());
    let digest = plan.digest()?;
    let approval = plan.approval_digest(PRINCIPAL)?;
    assert_eq!(
        DeletionPlan::decode(&plan.canonical_bytes()?, digest)?,
        plan
    );
    assert_eq!(
        plan_scope_deletion(&f.deployment, &plan.scope, &f.cx)?,
        plan
    );
    let wrong = request.clone().with_source_byte_budget(target + 1);
    assert!(matches!(
        commit_retention(
            &mut f.deployment,
            &wrong,
            digest,
            approval,
            PRINCIPAL,
            &f.cx
        ),
        Err(DeletionError::StalePlan(_))
    ));
    assert_eq!(snapshot(f.deployment.root())?, before);
    commit_retention(
        &mut f.deployment,
        &request,
        digest,
        approval,
        PRINCIPAL,
        &f.cx,
    )?;
    f.readable(middle)?;
    f.readable(newest)?;
    let after = snapshot(f.deployment.root())?;
    assert!(matches!(
        commit_retention(
            &mut f.deployment,
            &wrong,
            digest,
            approval,
            PRINCIPAL,
            &f.cx
        ),
        Err(DeletionError::StalePlan(_))
    ));
    assert_eq!(snapshot(f.deployment.root())?, after);
    assert_eq!(
        commit_retention(
            &mut f.deployment,
            &request,
            digest,
            approval,
            PRINCIPAL,
            &f.cx
        )?
        .outcome,
        CommitOutcome::AlreadyComplete
    );
    Ok(())
}

#[test]
fn byte_budget_counts_duplicate_inputs_once_and_frees_only_the_last_same_sensor_import()
-> TestResult {
    let mut f = Fixture::new("budget-duplicates")?;
    let first = f.ingest_at("first", 40, SENSOR, Some(0))?;
    let second = f.ingest_at("second", 40, SENSOR, Some(100))?;
    let distinct = f.ingest_at("distinct", 120, SENSOR, Some(200))?;
    assert_eq!(first.source, second.source);
    assert_ne!(first.source, distinct.source);
    let shared_bytes = f.source_bytes(first)?;
    let target = f.source_bytes(distinct)?;
    let request = request()?.with_source_byte_budget(target);
    let preview = plan_retention(&f.deployment, &request, &f.cx)?;
    let accounting = preview
        .assessment
        .selection
        .byte_accounting()
        .ok_or("accounting")?;
    assert_eq!(accounting.before_source_bytes, shared_bytes + target);
    assert_eq!(accounting.selected_source_bytes, shared_bytes);
    assert_eq!(accounting.projected_remaining_source_bytes, target);
    assert_eq!(accounting.unmet_source_bytes, 0);
    assert_eq!(preview.assessment.closure_evaluations, 3);
    let plan = preview.deletion.ok_or("duplicate cohort")?;
    assert_eq!(
        plan.imports.iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([first.identity, second.identity])
    );
    assert!(
        plan.deletable
            .iter()
            .any(|object| object.digest == first.source)
    );
    commit_retention(
        &mut f.deployment,
        &request,
        plan.digest()?,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &f.cx,
    )?;
    f.readable(distinct)?;
    assert!(f.deployment.publisher().spool().read(first.source).is_err());
    Ok(())
}

#[test]
fn byte_budget_under_target_is_read_only_and_age_floor_or_unknown_time_leaves_a_deficit()
-> TestResult {
    let mut f = Fixture::new("budget-age-floor")?;
    let old = f.ingest_at("old", 40, SENSOR, Some(0))?;
    let recent = f.ingest_at("recent", 40, SENSOR, Some(950))?;
    let unknown = f.ingest_at("unknown", 120, SENSOR, None)?;
    assert_eq!(old.source, recent.source);
    let total = f.source_bytes(old)? + f.source_bytes(unknown)?;
    let before = snapshot(f.deployment.root())?;
    let under = plan_retention(
        &f.deployment,
        &request()?.with_source_byte_budget(total),
        &f.cx,
    )?;
    assert!(under.deletion.is_none());
    assert_eq!(under.assessment.closure_evaluations, 0);
    assert_eq!(under.assessment.closure_scanned_objects, 0);
    assert_eq!(
        under
            .assessment
            .selection
            .candidates()
            .iter()
            .find(|c| c.import_identity() == old.identity)
            .ok_or("old")?
            .disposition(),
        RetentionDisposition::BudgetRetained
    );
    assert_eq!(
        under
            .assessment
            .selection
            .byte_accounting()
            .ok_or("accounting")?
            .selected_source_bytes,
        0
    );
    let request = request()?.with_source_byte_budget(0);
    let preview = plan_retention(&f.deployment, &request, &f.cx)?;
    assert_eq!(snapshot(f.deployment.root())?, before);
    let accounting = preview
        .assessment
        .selection
        .byte_accounting()
        .ok_or("accounting")?;
    assert_eq!(accounting.before_source_bytes, total);
    assert_eq!(accounting.selected_source_bytes, 0);
    assert_eq!(accounting.projected_remaining_source_bytes, total);
    assert_eq!(accounting.unmet_source_bytes, total);
    let states: BTreeMap<_, _> = preview
        .assessment
        .selection
        .candidates()
        .iter()
        .map(|c| (c.import_identity(), c.disposition()))
        .collect();
    assert_eq!(states[&recent.identity], RetentionDisposition::NotDue);
    assert_eq!(
        states[&unknown.identity],
        RetentionDisposition::CaptureTimeUnknown
    );
    let plan = preview
        .deletion
        .ok_or("old import can be removed with its shared source retained")?;
    assert_eq!(plan.imports, vec![old.identity]);
    assert!(
        !plan
            .deletable
            .iter()
            .any(|object| object.digest == old.source)
    );
    commit_retention(
        &mut f.deployment,
        &request,
        plan.digest()?,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &f.cx,
    )?;
    f.readable(recent)?;
    f.readable(unknown)?;
    let exhausted = plan_retention(&f.deployment, &request, &f.cx)?;
    assert!(exhausted.deletion.is_none());
    assert_eq!(
        exhausted
            .assessment
            .selection
            .byte_accounting()
            .ok_or("accounting")?
            .unmet_source_bytes,
        total
    );
    Ok(())
}

#[test]
fn byte_budget_keeps_held_recordings_explicit_and_reports_unmet_target_after_partial_cleanup()
-> TestResult {
    let mut f = Fixture::new("budget-held")?;
    let held = f.ingest_at("held", 40, SENSOR, Some(0))?;
    let held_bytes = f.source_bytes(held)?;
    f.hold("incident", held, HoldState::Held)?;
    let request = request()?.with_source_byte_budget(0);
    let blocked = plan_retention(&f.deployment, &request, &f.cx)?;
    assert!(blocked.deletion.is_none());
    assert_eq!(
        blocked
            .assessment
            .selection
            .byte_accounting()
            .ok_or("accounting")?
            .unmet_source_bytes,
        held_bytes
    );
    let free = f.ingest_at("free", 120, SENSOR, Some(100))?;
    let free_bytes = f.source_bytes(free)?;
    let preview = plan_retention(&f.deployment, &request, &f.cx)?;
    let candidate = preview
        .assessment
        .selection
        .candidates()
        .iter()
        .find(|c| c.import_identity() == held.identity)
        .ok_or("held")?;
    assert_eq!(
        candidate.disposition(),
        RetentionDisposition::ClosureBlocked
    );
    assert!(
        candidate
            .blockers()
            .iter()
            .any(|finding| finding.kind == "evidence_hold")
    );
    assert!(candidate.closure_witness().is_some());
    let accounting = preview
        .assessment
        .selection
        .byte_accounting()
        .ok_or("accounting")?;
    assert_eq!(accounting.before_source_bytes, held_bytes + free_bytes);
    assert_eq!(accounting.selected_source_bytes, free_bytes);
    assert_eq!(accounting.projected_remaining_source_bytes, held_bytes);
    assert_eq!(accounting.unmet_source_bytes, held_bytes);
    let plan = preview.deletion.ok_or("independent partial cleanup")?;
    assert!(plan.blockers.is_empty());
    assert_eq!(plan.imports, vec![free.identity]);
    commit_retention(
        &mut f.deployment,
        &request,
        plan.digest()?,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &f.cx,
    )?;
    f.readable(held)?;
    Ok(())
}

#[test]
fn byte_budget_checks_shared_effect_evidence_for_every_union_and_retains_the_deficit() -> TestResult
{
    let mut f = Fixture::new("budget-union-effect")?;
    let first = f.ingest_at("first", 40, SENSOR, Some(0))?;
    let second = f.ingest_at("second", 40, SENSOR, Some(100))?;
    let free = f.ingest_at("free", 120, SENSOR, Some(200))?;
    let shared_bytes = f.source_bytes(first)?;
    let free_bytes = f.source_bytes(free)?;
    let alert = f.pending_alert(first.source)?;
    for import in [first, second] {
        assert!(
            plan_deletion(&f.deployment, import.identity, &f.cx)?
                .blockers
                .is_empty()
        );
    }
    let request = request()?.with_source_byte_budget(0);
    let preview = plan_retention(&f.deployment, &request, &f.cx)?;
    let excluded = preview
        .assessment
        .selection
        .candidates()
        .iter()
        .find(|c| c.import_identity() == second.identity)
        .ok_or("blocked shared import")?;
    assert_eq!(excluded.disposition(), RetentionDisposition::ClosureBlocked);
    assert!(
        excluded
            .blockers()
            .iter()
            .any(|finding| finding.kind == "open_effect"
                && finding.subject == alert.intent.operation_id.as_str())
    );
    let accounting = preview
        .assessment
        .selection
        .byte_accounting()
        .ok_or("accounting")?;
    assert_eq!(accounting.before_source_bytes, shared_bytes + free_bytes);
    assert_eq!(accounting.selected_source_bytes, free_bytes);
    assert_eq!(accounting.projected_remaining_source_bytes, shared_bytes);
    assert_eq!(accounting.unmet_source_bytes, shared_bytes);
    let plan = preview.deletion.ok_or("safe partial union")?;
    assert!(plan.blockers.is_empty());
    assert_eq!(
        plan.imports.iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([first.identity, free.identity])
    );
    assert!(
        !plan
            .deletable
            .iter()
            .any(|object| object.digest == first.source)
    );
    commit_retention(
        &mut f.deployment,
        &request,
        plan.digest()?,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &f.cx,
    )?;
    f.readable(second)?;
    assert!(
        !f.deployment
            .effects()
            .operation(&alert.intent.operation_id)
            .ok_or("effect disappeared")?
            .state
            .is_terminal()
    );
    Ok(())
}

#[test]
fn byte_budget_logical_target_does_not_claim_physical_reclamation_of_other_sensor_sources()
-> TestResult {
    let mut f = Fixture::new("budget-physical")?;
    let other = f.ingest_at("other", 40, "sensor:other-camera", Some(0))?;
    let local = f.ingest("local", 40)?;
    assert_eq!(other.source, local.source);
    let bytes = f.source_bytes(local)?;
    f.hold("other-incident", other, HoldState::Held)?;
    let request = request()?.with_source_byte_budget(0);
    let preview = plan_retention(&f.deployment, &request, &f.cx)?;
    assert_eq!(preview.assessment.outside_sensor, 1);
    let accounting = preview
        .assessment
        .selection
        .byte_accounting()
        .ok_or("accounting")?;
    assert_eq!(accounting.before_source_bytes, bytes);
    assert_eq!(accounting.selected_source_bytes, bytes);
    assert_eq!(accounting.projected_remaining_source_bytes, 0);
    assert_eq!(accounting.unmet_source_bytes, 0);
    let plan = preview.deletion.ok_or("logical local eviction")?;
    assert!(
        !plan
            .deletable
            .iter()
            .any(|object| object.digest == local.source)
    );
    commit_retention(
        &mut f.deployment,
        &request,
        plan.digest()?,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &f.cx,
    )?;
    f.readable(other)?;
    Ok(())
}

#[test]
fn byte_budget_approval_is_invalidated_by_new_holds_and_later_imports() -> TestResult {
    let mut f = Fixture::new("budget-stale-inventory")?;
    let first = f.ingest("first", 40)?;
    let request = request()?.with_source_byte_budget(0);
    let prior = plan_retention(&f.deployment, &request, &f.cx)?
        .deletion
        .ok_or("plan")?;
    f.hold("new-incident", first, HoldState::Held)?;
    let before = snapshot(f.deployment.root())?;
    assert!(matches!(
        commit_retention(
            &mut f.deployment,
            &request,
            prior.digest()?,
            prior.approval_digest(PRINCIPAL)?,
            PRINCIPAL,
            &f.cx
        ),
        Err(DeletionError::StalePlan(_))
    ));
    assert_eq!(snapshot(f.deployment.root())?, before);
    f.hold("new-incident", first, HoldState::Released)?;
    let current = plan_retention(&f.deployment, &request, &f.cx)?
        .deletion
        .ok_or("released plan")?;
    let later = f.ingest("later", 120)?;
    let before = snapshot(f.deployment.root())?;
    assert!(matches!(
        commit_retention(
            &mut f.deployment,
            &request,
            current.digest()?,
            current.approval_digest(PRINCIPAL)?,
            PRINCIPAL,
            &f.cx
        ),
        Err(DeletionError::StalePlan(_))
    ));
    assert_eq!(snapshot(f.deployment.root())?, before);
    assert!(plan_scope_deletion(&f.deployment, &current.scope, &f.cx).is_err());
    f.readable(first)?;
    f.readable(later)?;
    Ok(())
}

#[test]
fn byte_budget_every_cleanup_cut_reopens_and_resumes_only_the_exact_bound_request() -> TestResult {
    for stage in DELETION_CUT_POINTS {
        let mut f = Fixture::new("budget-cold-retry")?;
        let held = f.ingest_at("held", 40, SENSOR, Some(0))?;
        let free = f.ingest_at("free", 120, SENSOR, Some(100))?;
        f.hold("incident", held, HoldState::Held)?;
        let request = request()?.with_source_byte_budget(0);
        let plan = plan_retention(&f.deployment, &request, &f.cx)?
            .deletion
            .ok_or("plan")?;
        let digest = plan.digest()?;
        let approval = plan.approval_digest(PRINCIPAL)?;
        f.cx.set_cancel_at_checkpoint(stage);
        assert!(
            matches!(commit_retention(&mut f.deployment, &request, digest,
            approval, PRINCIPAL, &f.cx), Err(DeletionError::Cancelled { stage: hit }) if hit == *stage)
        );
        let durable = DeletionIndex::read(&f.deployment)?.plan(digest).is_some();
        let mut f = f.reopen()?;
        let wrong = request.clone().with_source_byte_budget(1);
        let before = snapshot(f.deployment.root())?;
        assert!(matches!(
            commit_retention(
                &mut f.deployment,
                &wrong,
                digest,
                approval,
                PRINCIPAL,
                &f.cx
            ),
            Err(DeletionError::StalePlan(_))
        ));
        assert_eq!(snapshot(f.deployment.root())?, before);
        let receipt = commit_retention(
            &mut f.deployment,
            &request,
            digest,
            approval,
            PRINCIPAL,
            &f.cx,
        )?;
        assert_eq!(
            receipt.outcome,
            if durable {
                CommitOutcome::Resumed
            } else {
                CommitOutcome::Completed
            }
        );
        assert_eq!(receipt.plan, plan);
        f.readable(held)?;
        assert!(
            RetainedFileImport::open(
                &f.deployment,
                free.identity,
                RetainedReadLimits::default(),
                &f.cx
            )
            .is_err()
        );
        assert_eq!(
            commit_retention(
                &mut f.deployment,
                &request,
                digest,
                approval,
                PRINCIPAL,
                &f.cx
            )?
            .outcome,
            CommitOutcome::AlreadyComplete
        );
    }
    Ok(())
}
