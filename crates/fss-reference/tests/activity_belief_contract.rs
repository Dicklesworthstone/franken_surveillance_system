#![forbid(unsafe_code)]
//! Concrete native derivation through real retained results, ledgered roots and cold disk capture.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use fss_codec_mjpeg::color::{RgbDecodeLimits, decode_rgb};
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget};
use fss_core::{
    BatchId, BeliefInterval, BudgetVector, CanonicalDecode, CanonicalEncode, CapsuleId,
    CaptureInterval, ClockBasis, ContentDigest, ContextAuthority, DerivedBelief, DerivedBeliefParams,
    KnowledgeState, OperationId, ProvenanceClass, RootAuthoritySpec, SensorCapsule, SensorId,
    SensorSourceBytesSpec, StreamId, TimestampNs,
};
use fss_object::HostSpoolIo;
use fss_publication::custody_audit::belief_snapshot::durable::{
    DurableBeliefError, DurableBeliefLimits, DurableBeliefRequest, VerifiedDurableBelief,
    verify_durable_belief,
};
use fss_publication::{SlotName, root_reachability_object_id};
use fss_reference::activity_replay::belief::{
    ACTIVITY_BELIEF_ALGORITHM, ACTIVITY_BELIEF_GENERATION, ActivityBeliefEngine,
    ActivityEvidenceBinding, ActivityEvidenceSet,
};
use fss_reference::activity_replay::{ActivityReplayLimits, ActivityReplayPlan};
use fss_reference::executor_activity::{
    ActivityExecutorModel, ActivityFrameBinding, ActivityThresholdPolicy, ExecutorModelOutcome,
    ExecutorModelResult, open_retained_executor_result, retain_executor_result,
    rgb_decode_receipt_bytes,
};
use fss_reference::{ADP_REPLAY_ROW_ID, ExecBudget, ReferenceDeployment, ReplayCx,
    ReplayIoAuthority, ScalarExecCx};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const BACKGROUND: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/background.jpg");
const GRADIENT: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/gray.jpg");
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> TestResult<Self> {
        for _ in 0..64 {
            let path = std::env::temp_dir().join(format!("fss-activity-belief-{}-{}",
                std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("scratch identity allowance exhausted".into())
    }
}
impl Drop for Scratch {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}
fn context(root: &Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:activity-belief-test".to_owned(),
        operation_id: OperationId::parse("operation:activity-belief-test")?,
        principal: "operator:activity-belief-test".to_owned(),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()], deadline: None, priority: 10,
        budgets: BudgetVector::default(), privacy_scope: "privacy:internal".to_owned(),
        retention_scope: "retention:ephemeral".to_owned(),
        anchor_universe: ContentDigest::sha256(b"activity-belief-test-universe"), generation: 1,
    })?;
    Ok(ReplayCx::new(ReplayIoAuthority::from_context_authority(&authority, root.join("scratch"))?))
}
fn capsule(bytes: &[u8], sequence: u64) -> TestResult<SensorCapsule> {
    let capture = CaptureInterval::new(TimestampNs(0), TimestampNs(5_000_000_000))?;
    Ok(SensorCapsule::from_source_bytes(SensorSourceBytesSpec {
        capsule_id: CapsuleId::parse(format!("capsule:belief:{sequence}"))?,
        sensor_id: SensorId::parse("sensor:belief")?, stream_id: StreamId::parse("stream:belief")?,
        sequence, capture, receive_time: capture.latest, clock_basis: ClockBasis::Estimated,
        source: bytes, frame_count: 1, gap_before: false,
    })?)
}

struct Fixture {
    deployment: ReferenceDeployment,
    plan: ActivityReplayPlan,
    evidence: ActivityEvidenceSet,
    slots: Vec<SlotName>,
    result: ExecutorModelResult,
    // Dropped last, after the publisher's locks and journal handles.
    scratch: Scratch,
}
fn fixture(quiet: bool, altered_result: bool) -> TestResult<Fixture> {
    let scratch = Scratch::new()?;
    let cx = context(&scratch.0)?;
    let root = scratch.0.join("deployment");
    let mut deployment = ReferenceDeployment::open(&root, "site:activity-belief", &cx)?;
    let scalar = ScalarExecCx::new();
    let model = ActivityExecutorModel::load_committed(&scalar)?;
    let plan = ActivityReplayPlan {
        sensor_id: SensorId::parse("sensor:belief")?, stream_id: StreamId::parse("stream:belief")?,
        job_id: "job:belief".to_owned(), policy: ActivityThresholdPolicy::reference()?,
        interpretation: ComponentInterpretation::Grayscale,
        execution: ExecBudget::new(10_000_000, 16 * 1024 * 1024),
    };
    let frame_source = if quiet { BACKGROUND } else { GRADIENT };
    let decode = |bytes: &[u8]| decode_rgb(bytes, ContentDigest::sha256(bytes).bytes(),
        plan.interpretation, RgbDecodeLimits::default(), &mut DecodeBudget::new(20_000_000));
    let frame = decode(frame_source)?;
    let reference = decode(BACKGROUND)?;
    let fc = capsule(frame_source, 1)?;
    let rc = capsule(BACKGROUND, 0)?;
    let (mut result, receipt) = model.invoke(&plan.sensor_id,
        ActivityFrameBinding { pixels: frame.pixels(), receipt: frame.receipt(),
            source_digest: fc.source_digest, capsule: &fc },
        ActivityFrameBinding { pixels: reference.pixels(), receipt: reference.receipt(),
            source_digest: rc.source_digest, capsule: &rc },
        &plan.policy, plan.execution, &plan.job_id, &scalar)?;
    if altered_result {
        result.outcome = ExecutorModelOutcome::NoActivity { score_bits: 0.0_f32.to_bits() };
    }
    let source_objects = [frame_source.to_vec(), BACKGROUND.to_vec(), fc.try_canonical_bytes()?,
        rc.try_canonical_bytes()?, rgb_decode_receipt_bytes(&frame.receipt()),
        rgb_decode_receipt_bytes(&reference.receipt())];
    let source_slot = SlotName::parse("activity-originals")?;
    let refs: Vec<_> = source_objects.iter().map(Vec::as_slice).collect();
    let staged = deployment.stage_and_publish(&source_slot, &refs, &cx)?;
    let _ = deployment.publish_and_commit(&source_slot, &staged.manifest, fc.capture, &cx)?;
    // Use the pre-existing real retention writer; it stores native result/receipt as cognition.
    let retained = retain_executor_result(&mut deployment, &result, &receipt, fc.capture, &cx)?;
    let result_slot = deployment.publisher().visible_roots().find(|entry| entry.root == retained.root)
        .ok_or("result root not published")?.slot.clone();
    let source_id = root_reachability_object_id(&source_slot)?;
    let result_id = root_reachability_object_id(&result_slot)?;
    let source_revision = deployment.ledger().current().objects.get(&source_id).ok_or("source revision")?.clone();
    let result_revision = deployment.ledger().current().objects.get(&result_id).ok_or("result revision")?.clone();
    let source = |index: usize| ActivityEvidenceBinding { digest: ContentDigest::sha256(&source_objects[index]),
        authority: source_id.clone(), revision: source_revision.clone() };
    let evidence = ActivityEvidenceSet {
        result: ActivityEvidenceBinding { digest: result.object_digest(), authority: result_id.clone(), revision: result_revision.clone() },
        invocation: ActivityEvidenceBinding { digest: result.invocation_receipt_object, authority: result_id, revision: result_revision },
        frame_source: source(0), reference_source: source(1), frame_capsule: source(2),
        reference_capsule: source(3), frame_decode: source(4), reference_decode: source(5),
    };
    let mut slots = vec![source_slot, result_slot];
    slots.sort();
    drop(deployment);
    // Every test starts from a cold reopened native deployment, not an in-memory reconstruction.
    let deployment = ReferenceDeployment::reopen(&root, "site:activity-belief", &cx)?;
    let opened = open_retained_executor_result(&deployment, result.object_digest(), &cx)?;
    assert_eq!(opened.result, result);
    Ok(Fixture { deployment, plan, evidence, slots, result, scratch })
}
fn engine<'a>(f: &Fixture, cx: &'a ScalarExecCx, budget: u64) -> TestResult<ActivityBeliefEngine<'a>> {
    Ok(ActivityBeliefEngine::load_committed(f.plan.clone(), f.evidence.clone(),
        ActivityReplayLimits::default(), DecodeBudget::new(budget), cx)?)
}
fn verify<'a>(f: &'a Fixture, engine: &ActivityBeliefEngine<'_>, offered: &DerivedBelief)
    -> Result<VerifiedDurableBelief<'a>, DurableBeliefError>
{
    verify_durable_belief(&offered.canonical_bytes(), f.deployment.ledger(), f.deployment.publisher(),
        &HostSpoolIo, engine, DurableBeliefRequest { slots: &f.slots, denied: &BTreeMap::new(),
            limits: DurableBeliefLimits::default(), cancelled: &|| false })
}
fn tree(root: &Path) -> TestResult<BTreeMap<PathBuf, ContentDigest>> {
    let mut result = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() { pending.push(entry.path()); }
            else { result.insert(entry.path().strip_prefix(root)?.to_path_buf(), ContentDigest::sha256(&fs::read(entry.path())?)); }
        }
    }
    Ok(result)
}
fn reseal(offered: &DerivedBelief, statement: String, interval: BeliefInterval,
    supporting: Vec<ContentDigest>, contradictions: Vec<ContentDigest>) -> TestResult<DerivedBelief>
{
    Ok(DerivedBelief::new(DerivedBeliefParams {
        belief_id: offered.belief_id().to_owned(), anchor: offered.anchor().clone(),
        generation: ACTIVITY_BELIEF_GENERATION, algorithm_id: ACTIVITY_BELIEF_ALGORITHM.to_owned(),
        statement, knowledge_state: KnowledgeState::Estimated, provenance: ProvenanceClass::Derived,
        uncertainty: interval, supporting_evidence: supporting, contradictions,
        derivation_receipt: ContentDigest::sha256(b"unsealed"),
    }.with_computed_receipt()?)?)
}

#[test]
fn cold_native_result_becomes_verified_cognition_only_after_original_frame_replay() -> TestResult {
    let f = fixture(false, false)?;
    let before = tree(f.deployment.root())?;
    let cx = ScalarExecCx::new();
    let engine = engine(&f, &cx, 20_000_000)?;
    let offered = engine.offer(&f.result, f.deployment.current_anchor())?;
    assert!(!engine.attempted());
    let verified = verify(&f, &engine, &offered)?;
    assert_eq!(verified.belief(), &offered);
    assert_eq!(verified.graph_usage().derivations, 1);
    assert!(verified.custody_audit().all_verified());
    assert!(engine.decode_work_used() > 0);
    assert!(verified.belief().statement().contains("uncalibrated"));
    assert!(!verified.to_knowledge_cell(&|| false)?.is_irreversible_effect_premise(TimestampNs(5_000_000_000)));
    let ancestry = verified.ancestry(f.evidence.frame_source.digest).ok_or("missing source ancestry")?;
    assert!(ancestry.iter().any(|path| path.object_id() == &f.evidence.frame_source.authority));
    assert_eq!(before, tree(f.deployment.root())?);
    assert_eq!(f.deployment.ledger().batches().len(), 3);
    Ok(())
}

#[test]
fn quiet_equal_payload_roles_are_deduplicated_without_becoming_an_absence_certificate() -> TestResult {
    let f = fixture(true, false)?;
    let cx = ScalarExecCx::new();
    let engine = engine(&f, &cx, 20_000_000)?;
    assert!(engine.supporting_roots().len() < 8);
    let offered = engine.offer(&f.result, f.deployment.current_anchor())?;
    let verified = verify(&f, &engine, &offered)?;
    assert!(verified.belief().statement().contains("no_activity"));
    assert!(verified.belief().statement().contains("no presence or absence claim"));
    assert!(!verified.to_knowledge_cell(&|| false)?.is_irreversible_effect_premise(TimestampNs(5_000_000_000)));
    Ok(())
}

#[test]
fn the_existing_retention_writer_does_not_make_an_altered_score_replayable() -> TestResult {
    let f = fixture(false, true)?;
    let cx = ScalarExecCx::new();
    let engine = engine(&f, &cx, 20_000_000)?;
    let offered = engine.offer(&f.result, f.deployment.current_anchor())?;
    assert!(matches!(verify(&f, &engine, &offered), Err(DurableBeliefError::Graph(_))));
    assert!(engine.attempted());
    assert!(engine.decode_work_used() > 0);
    Ok(())
}

#[test]
fn resealed_statements_and_confidence_do_not_replace_independent_rederivation() -> TestResult {
    let f = fixture(false, false)?;
    for confidence in [false, true] {
        let cx = ScalarExecCx::new();
        let engine = engine(&f, &cx, 20_000_000)?;
        let honest = engine.offer(&f.result, f.deployment.current_anchor())?;
        let offered = reseal(&honest,
            if confidence { honest.statement().to_owned() } else { "a person is certainly present".to_owned() },
            if confidence { BeliefInterval::new(990_000, 1_000_000)? } else { BeliefInterval::new(0, 1_000_000)? },
            honest.supporting_evidence().to_vec(), vec![])?;
        assert!(matches!(verify(&f, &engine, &offered), Err(DurableBeliefError::Graph(_))));
        assert!(engine.decode_work_used() > 0);
    }
    Ok(())
}

#[test]
fn omitted_roles_and_reclassified_contradictions_fail_before_native_execution() -> TestResult {
    let f = fixture(false, false)?;
    for contradict in [false, true] {
        let cx = ScalarExecCx::new();
        let engine = engine(&f, &cx, 20_000_000)?;
        let honest = engine.offer(&f.result, f.deployment.current_anchor())?;
        let root = f.evidence.reference_capsule.digest;
        let supporting = honest.supporting_evidence().iter().copied().filter(|digest| *digest != root).collect();
        let offered = reseal(&honest, honest.statement().to_owned(), BeliefInterval::new(0, 1_000_000)?,
            supporting, if contradict { vec![root] } else { vec![] })?;
        assert!(matches!(verify(&f, &engine, &offered), Err(DurableBeliefError::Graph(_))));
        assert!(!engine.attempted());
        assert_eq!(engine.decode_work_used(), 0);
    }
    Ok(())
}

#[test]
fn expected_authority_revisions_are_not_substituted_by_equal_payload_membership() -> TestResult {
    let mut f = fixture(false, false)?;
    // All source roles name one consistent but WRONG expected validity revision.
    for binding in [&mut f.evidence.frame_source, &mut f.evidence.reference_source,
        &mut f.evidence.frame_capsule, &mut f.evidence.reference_capsule,
        &mut f.evidence.frame_decode, &mut f.evidence.reference_decode] {
        binding.revision.validity.latest = TimestampNs(6_000_000_000);
    }
    let cx = ScalarExecCx::new();
    let engine = engine(&f, &cx, 20_000_000)?;
    let offered = engine.offer(&f.result, f.deployment.current_anchor())?;
    assert!(matches!(verify(&f, &engine, &offered), Err(DurableBeliefError::Graph(_))));
    assert!(!engine.attempted());
    Ok(())
}

#[test]
fn extra_deny_set_and_source_removal_refuse_before_the_derivation_engine() -> TestResult {
    let f = fixture(false, false)?;
    let cx = ScalarExecCx::new();
    let engine = engine(&f, &cx, 20_000_000)?;
    let offered = engine.offer(&f.result, f.deployment.current_anchor())?;
    let denied = BTreeMap::from([(f.evidence.reference_source.digest, ContentDigest::sha256(b"explicit test denial"))]);
    assert!(matches!(verify_durable_belief(&offered.canonical_bytes(), f.deployment.ledger(), f.deployment.publisher(),
        &HostSpoolIo, &engine, DurableBeliefRequest { slots: &f.slots, denied: &denied,
            limits: DurableBeliefLimits::default(), cancelled: &|| false }), Err(DurableBeliefError::Capture(_))));
    assert!(!engine.attempted());
    // Remove only the test's original-source publication record; surviving copied bytes do not
    // substitute for the exact selected durable slot. No production deletion API is bypassed.
    let source_slot = f.slots.iter().find(|slot| slot.as_str() == "activity-originals").ok_or("source slot")?;
    fs::remove_file(f.deployment.publisher().root_dir().join("roots").join(format!("{source_slot}.root")))?;
    assert!(verify(&f, &engine, &offered).is_err());
    assert!(!engine.attempted());
    Ok(())
}

#[test]
fn stale_authority_and_deletion_prefixed_histories_do_not_start_replay() -> TestResult {
    for deletion in [false, true] {
        let mut f = fixture(false, false)?;
        let cx = ScalarExecCx::new();
        let engine = engine(&f, &cx, 20_000_000)?;
        let old = engine.offer(&f.result, f.deployment.current_anchor())?;
        let replay_cx = context(&f.scratch.0)?;
        let id = if deletion { "batch:deletion:test-prefix" } else { "batch:later" };
        let _ = f.deployment.append_batch(BatchId::parse(id)?, vec![], vec![], &replay_cx)?;
        let offered = if deletion { engine.offer(&f.result, f.deployment.current_anchor())? } else { old };
        let result = verify(&f, &engine, &offered);
        if deletion { assert!(matches!(result, Err(DurableBeliefError::DeletionAdapterRequired))); }
        else { assert!(matches!(result, Err(DurableBeliefError::Contract(_)))); }
        assert!(!engine.attempted());
    }
    Ok(())
}

#[test]
fn one_native_attempt_and_consumed_decode_work_cannot_be_reset_by_repeated_verification() -> TestResult {
    let f = fixture(false, false)?;
    let cx = ScalarExecCx::new();
    let engine = engine(&f, &cx, 20_000_000)?;
    let offered = engine.offer(&f.result, f.deployment.current_anchor())?;
    assert!(verify(&f, &engine, &offered).is_ok());
    let used = engine.decode_work_used();
    assert!(used > 0);
    assert!(matches!(verify(&f, &engine, &offered), Err(DurableBeliefError::Graph(_))));
    assert_eq!(engine.decode_work_used(), used);
    let cx = ScalarExecCx::new();
    let starved = ActivityBeliefEngine::load_committed(f.plan.clone(), f.evidence.clone(),
        ActivityReplayLimits::default(), DecodeBudget::new(used - 1), &cx)?;
    assert!(matches!(verify(&f, &starved, &offered), Err(DurableBeliefError::Graph(_))));
    assert!(starved.attempted());
    assert!(starved.decode_work_used() > 0);
    Ok(())
}

#[test]
fn independent_semantic_configuration_changes_proposition_identity_not_read_authority() -> TestResult {
    let f = fixture(false, false)?;
    let cx = ScalarExecCx::new();
    let original = engine(&f, &cx, 20_000_000)?;
    let mut plan = f.plan.clone();
    plan.job_id = "job:another-invocation".to_owned();
    let changed = ActivityBeliefEngine::load_committed(plan, f.evidence.clone(), ActivityReplayLimits::default(),
        DecodeBudget::new(20_000_000), &cx)?;
    assert_ne!(original.belief_id(), changed.belief_id());
    let old_offer = original.offer(&f.result, f.deployment.current_anchor())?;
    assert!(matches!(verify(&f, &changed, &old_offer), Err(DurableBeliefError::Graph(_))));
    assert!(!changed.attempted());
    Ok(())
}

#[test]
fn cooperative_cancellation_fences_cold_capture_and_native_execution() -> TestResult {
    let f = fixture(false, false)?;
    let cx = ScalarExecCx::new();
    let flag = AtomicBool::new(false);
    let engine = ActivityBeliefEngine::load_committed(f.plan.clone(), f.evidence.clone(),
        ActivityReplayLimits::default(), DecodeBudget::cancellable(20_000_000, &flag), &cx)?;
    let offered = engine.offer(&f.result, f.deployment.current_anchor())?;
    flag.store(true, Ordering::Release);
    assert!(matches!(verify_durable_belief(&offered.canonical_bytes(), f.deployment.ledger(), f.deployment.publisher(),
        &HostSpoolIo, &engine, DurableBeliefRequest { slots: &f.slots, denied: &BTreeMap::new(),
            limits: DurableBeliefLimits::default(), cancelled: &|| flag.load(Ordering::Acquire) || cx.is_cancelled() }),
        Err(DurableBeliefError::Cancelled)));
    assert!(!engine.attempted());
    assert_eq!(engine.decode_work_used(), 0);
    Ok(())
}

#[test]
fn untrusted_saved_belief_bytes_still_require_canonical_intake() -> TestResult {
    let f = fixture(false, false)?;
    let cx = ScalarExecCx::new();
    let engine = engine(&f, &cx, 20_000_000)?;
    let offered = engine.offer(&f.result, f.deployment.current_anchor())?;
    let bytes = offered.try_canonical_bytes()?;
    assert_eq!(DerivedBelief::from_canonical_bytes(&bytes)?, offered);
    for end in 0..bytes.len() {
        assert!(verify_durable_belief(&bytes[..end], f.deployment.ledger(), f.deployment.publisher(),
            &HostSpoolIo, &engine, DurableBeliefRequest { slots: &f.slots, denied: &BTreeMap::new(),
                limits: DurableBeliefLimits::default(), cancelled: &|| false }).is_err());
    }
    assert!(!engine.attempted());
    Ok(())
}
