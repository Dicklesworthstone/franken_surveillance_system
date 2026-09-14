#![forbid(unsafe_code)]
//! Deterministic recovery and failure contract tests for [`ReferenceDeployment`].

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use fss_core::{
    BatchId, CapsuleId, CaptureInterval, ContentDigest, ContractBasis, ContractBasisRegistryBytes,
    EventId, EvidenceDelta, HandoffId, MissionId, ObjectId, OperationId, Plane, PrincipalId,
    ProbabilityInterval, SensorId, SessionId, TimestampNs,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy, doctor_path};
use fss_object::{InMemoryObjectStore, ObjectLimits, ObjectManifest};
use fss_publication::{
    LOCAL_ROOTS_DIR, LedgerCutPoint, LocalPublicationError, LocalPublicationState, PublishCutPoint,
    ROOT_RECORD_SUFFIX, ROOT_TEMP_SUFFIX, SlotName,
};
use fss_reference::{
    DEPLOYMENT_LAYOUT_FILENAME, DeploymentLayout, DeploymentLimits, HostLayoutIo, LayoutIo,
    RecoveryAction, RecoveryReceipt, ReferenceAlertPlan, ReferenceDeployment, ReferenceError,
    ReferenceEventReceipt, ReferencePolicyDecision, ReferenceProviderBehavior,
    ReferenceSituationRequest, ReplayCx, write_layout_atomic,
};
use fss_reference::{
    DeliveryPlan, MockModelScript, MockModelSpec, MockSemanticLabel, ReferenceModelObservation,
    VirtualCameraSpec, execute_mock_model, run_reference_capture,
};

type R = Result<(), Box<dyn Error>>;

fn tdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("fss-refdep-recovery-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    let _ = fs::remove_file(&d);
    d
}

fn test_cx(label: &str) -> Result<ReplayCx, Box<dyn Error>> {
    let spec = fss_core::RootAuthoritySpec {
        trace_id: format!("trace:test-{label}"),
        operation_id: OperationId::parse(format!("operation:test-{label}"))?,
        principal: format!("operator:test-{label}"),
        capabilities: vec![fss_reference::ADP_REPLAY_ROW_ID.to_string()],
        deadline: None,
        priority: 10,
        budgets: fss_core::BudgetVector::default(),
        privacy_scope: "privacy:internal".to_string(),
        retention_scope: "retention:ephemeral".to_string(),
        anchor_universe: ContentDigest::sha256(b"test-anchor-universe"),
        generation: 1,
    };
    let root_auth = fss_core::ContextAuthority::new_root(spec)?;
    let scratch_root = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(format!(
            "test-replay-cx-refdep-recovery-{label}-{}",
            std::process::id()
        ));
    let io = fss_reference::ReplayIoAuthority::from_context_authority(&root_auth, scratch_root)?;
    Ok(ReplayCx::new(io))
}

fn err_of<T>(r: Result<T, ReferenceError>) -> Result<ReferenceError, Box<dyn Error>> {
    match r {
        Ok(_) => Err("expected Err, got Ok".into()),
        Err(e) => Ok(e),
    }
}

fn iv(a: i128, b: i128) -> Result<CaptureInterval, Box<dyn Error>> {
    Ok(CaptureInterval::new(TimestampNs(a), TimestampNs(b))?)
}

fn delta(id: &str, obj: &str, payload: ContentDigest) -> Result<EvidenceDelta, Box<dyn Error>> {
    Ok(EvidenceDelta {
        delta_id: id.to_owned(),
        family: "sensor_capsule".to_owned(),
        object_id: ObjectId::parse(obj)?,
        prior_generation: None,
        new_generation: 1,
        validity: iv(100, 200)?,
        plane: Plane::Authority,
        payload_digest: payload,
        witness_digest: None,
        operation_id: None,
    })
}

fn append_raw(path: &Path, bytes: &[u8]) -> R {
    let mut f = OpenOptions::new().append(true).open(path)?;
    f.write_all(bytes)?;
    f.flush()?;
    Ok(())
}

fn sample_situation_request<'a>(
    decision: &'a ReferencePolicyDecision,
    receipt: &'a ReferenceEventReceipt,
) -> Result<ReferenceSituationRequest<'a>, Box<dyn Error>> {
    Ok(ReferenceSituationRequest {
        mission_id: MissionId::parse("mission:situation:test")?,
        session_id: SessionId::parse("session:situation:test")?,
        principal_id: PrincipalId::parse("principal:situation:test")?,
        objective_id: "objective:protect-reference-boundary".to_owned(),
        revision: 1,
        contract_basis: ContractBasis::from_registry_bytes(
            ContractBasisRegistryBytes::new(
                b"schemas",
                b"operations",
                b"views",
                b"capabilities",
                b"errors",
                b"costs",
                "fss-reference:test",
            )
            .with_accepted_nightly("nightly-2026-08-31"),
        ),
        previous_anchor: None,
        predecessor_publication: None,
        decision,
        event_receipt: receipt,
        alert_plan: None,
        alert_outcome: None,
        coverage_witness: None,
        available_capabilities: [
            "capability:alert.prepare".to_owned(),
            "capability:alert.commit".to_owned(),
            fss_reference::CAPABILITY_EFFECT_RECONCILE.to_owned(),
        ]
        .into_iter()
        .collect(),
        created_at: TimestampNs(1_000),
    })
}

fn listing(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = match fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect(),
        Err(e) => vec![format!("<read_dir err {e}>")],
    };
    v.sort();
    v
}

/// Whether this process is refused by directory permission bits. A privileged runner (for
/// example a root build worker) bypasses them, so a permission-denied branch cannot be observed
/// there and the test asserts the literal privileged outcome instead.
fn permission_bits_enforced(dir: &Path) -> Result<bool, Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;
    let probe = dir.join("permission-probe");
    fs::create_dir_all(&probe)?;
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o555))?;
    let enforced = fs::create_dir(probe.join("child")).is_err();
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o755))?;
    fs::remove_dir_all(&probe)?;
    Ok(enforced)
}

/// Builds a policy decision corroborated by two independent virtual cameras whose captures are
/// committed in the deployment ledger, and stages the model receipts in the deployment spool.
fn corroborated_decision(
    dep: &mut ReferenceDeployment,
    event: &str,
    cx: &ReplayCx,
) -> Result<ReferencePolicyDecision, Box<dyn Error>> {
    let captures_path = std::env::temp_dir().join(format!(
        "fss-refdep-captures-{}-{}.journal",
        event.replace(':', "-"),
        std::process::id()
    ));
    let _stale = fs::remove_file(&captures_path);
    let mut captures = DurableReferenceLedger::open(
        &captures_path,
        "site:refdep-captures",
        IncompleteTailPolicy::Reject,
    )?;
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(512, 8 * 1024 * 1024));
    let mut observations = Vec::new();
    for (name, seed) in [("alpha", 111), ("beta", 222)] {
        let spec = VirtualCameraSpec {
            capture_id: CapsuleId::parse(format!("capture:cam:{name}"))?,
            sensor_id: SensorId::parse(format!("sensor:cam:{name}"))?,
            seed,
            packet_count: 2,
            packet_bytes: 32,
            start_ns: 10_000,
            period_ns: 1_000_000,
            uncertainty_ns: 1_000,
        };
        let capture = run_reference_capture(
            &spec,
            &DeliveryPlan::identity(spec.packet_count)?,
            &mut objects,
            &mut captures,
        )?;
        let model = MockModelSpec::new(
            format!("mock:cam:{name}:v1"),
            MockModelScript::Fixed {
                label: MockSemanticLabel::PersonLike,
                probability: ProbabilityInterval::new(0.99, 1.0)?,
            },
        )?;
        let result = execute_mock_model(&model, &capture, &mut objects)?;
        observations.push(ReferenceModelObservation::new(
            result,
            format!("power:cam:{name}"),
            CaptureInterval::new(TimestampNs(10_000), TimestampNs(20_000))?,
        )?);
    }
    let decision = dep.evaluate_policy(EventId::parse(event)?, observations, cx)?;
    for receipt in &decision.event.model_receipts {
        let staged = dep.stage_payload(objects.read_verified(*receipt)?)?;
        assert_eq!(staged, *receipt);
    }
    Ok(decision)
}

#[test]
fn p01_lock_path_exact_and_recovery_locked() -> R {
    let d = tdir("p01");
    let cx = test_cx("p01")?;
    let dep = ReferenceDeployment::open(&d, "site:p01", &cx)?;
    let e = err_of(ReferenceDeployment::open(&d, "site:p01", &cx))?;
    println!("PROBE p01 second open: {e:?}");
    match &e {
        ReferenceError::DeploymentLocked { path } => {
            assert_eq!(path, &d.join("objects").join("LOCK"))
        }
        other => return Err(format!("p01 unexpected {other:?}").into()),
    }
    let e2 = err_of(ReferenceDeployment::open_for_recovery(
        &d,
        RecoveryAction::TruncateIncompleteLedgerTail,
        &cx,
    ))?;
    println!("PROBE p01 recovery while held: {e2:?}");
    match &e2 {
        ReferenceError::DeploymentLocked { path } => {
            assert_eq!(path, &d.join("objects").join("LOCK"))
        }
        other => return Err(format!("p01 recovery unexpected {other:?}").into()),
    }
    drop(dep);
    let _ = fs::remove_dir_all(&d);
    Ok(())
}

#[test]
fn p02_lock_taken_before_journals() -> R {
    let d = tdir("p02");
    let cx = test_cx("p02")?;
    let dep = ReferenceDeployment::open(&d, "site:p02", &cx)?;
    let lp = d.join("ledger/journal.fssj");
    let ep = d.join("effects/journal.fssj");
    append_raw(&lp, b"FSSJRN01\x00\x01torn")?;
    append_raw(&ep, b"FSSJRN01\x00\x01torn")?;
    let lb = fs::read(&lp)?;
    let eb = fs::read(&ep)?;
    let e = err_of(ReferenceDeployment::open(&d, "site:p02", &cx))?;
    println!("PROBE p02 second open with torn journals while locked: {e:?}");
    assert!(
        matches!(e, ReferenceError::DeploymentLocked { .. }),
        "journal opened before lock: {e:?}"
    );
    assert_eq!(fs::read(&lp)?, lb);
    assert_eq!(fs::read(&ep)?, eb);
    drop(dep);
    let _ = fs::remove_dir_all(&d);
    Ok(())
}

#[test]
fn p03_layout_exact_and_no_temp_leftover() -> R {
    let d = tdir("p03");
    let cx = test_cx("p03")?;
    let dep = ReferenceDeployment::open(&d, "site:p03", &cx)?;
    let text = fs::read_to_string(d.join(DEPLOYMENT_LAYOUT_FILENAME))?;
    println!("PROBE p03 LAYOUT text:\n{text}");
    assert_eq!(text, dep.layout_report().to_canonical_text());
    let l = listing(&d);
    println!("PROBE p03 root listing: {l:?}");
    assert_eq!(l, vec!["LAYOUT", "effects", "ledger", "objects"]);
    drop(dep);
    let _ = fs::remove_dir_all(&d);
    Ok(())
}

#[test]
fn p04_reopen_same_params_is_noop() -> R {
    use std::os::unix::fs::MetadataExt;
    let d = tdir("p04");
    let cx = test_cx("p04")?;
    drop(ReferenceDeployment::open(&d, "site:p04", &cx)?);
    let lay = d.join(DEPLOYMENT_LAYOUT_FILENAME);
    let (b0, i0) = (fs::read(&lay)?, fs::metadata(&lay)?.ino());
    let lj0 = fs::read(d.join("ledger/journal.fssj"))?;
    drop(ReferenceDeployment::open(&d, "site:p04", &cx)?);
    let (b1, i1) = (fs::read(&lay)?, fs::metadata(&lay)?.ino());
    println!(
        "PROBE p04 inode before {i0} after {i1}; bytes equal {}",
        b0 == b1
    );
    assert_eq!(b0, b1);
    assert_eq!(i0, i1, "LAYOUT rewritten on reopen");
    assert_eq!(lj0, fs::read(d.join("ledger/journal.fssj"))?);
    let _ = fs::remove_dir_all(&d);
    Ok(())
}

#[test]
fn p05_reopen_different_params_refused_typed() -> R {
    let d = tdir("p05");
    let cx = test_cx("p05")?;
    drop(ReferenceDeployment::open(&d, "site:p05", &cx)?);
    let lay0 = fs::read(d.join(DEPLOYMENT_LAYOUT_FILENAME))?;
    let e = err_of(ReferenceDeployment::open(&d, "site:other", &cx))?;
    match e {
        ReferenceError::SiteLineageMismatch { expected, actual } => {
            assert_eq!(expected, "site:other");
            assert_eq!(actual, "site:p05");
        }
        other => return Err(format!("p05 expected SiteLineageMismatch, got {other:?}").into()),
    }
    let lim = DeploymentLimits {
        spool_object_max_bytes: 1024,
        ..DeploymentLimits::standard()
    };
    let e2 = err_of(ReferenceDeployment::open_with_limits(
        &d, "site:p05", lim, &cx,
    ))?;
    match e2 {
        ReferenceError::LimitsDigestMismatch { expected, actual } => {
            assert_eq!(expected, lim.canonical_digest()?);
            assert_eq!(actual, DeploymentLimits::standard().canonical_digest()?);
        }
        other => return Err(format!("p05 expected LimitsDigestMismatch, got {other:?}").into()),
    }
    assert_eq!(lay0, fs::read(d.join(DEPLOYMENT_LAYOUT_FILENAME))?);
    let _ = fs::remove_dir_all(&d);
    Ok(())
}

#[test]
fn p06_crash_skeleton_without_layout() -> R {
    let cx = test_cx("p06")?;
    let d = tdir("p06a");
    fs::create_dir_all(d.join("objects"))?;
    fs::create_dir_all(d.join("ledger"))?;
    let r = ReferenceDeployment::open(&d, "site:p06", &cx);
    assert!(r.is_ok(), "skeleton open must succeed: {r:?}");
    assert!(d.join(DEPLOYMENT_LAYOUT_FILENAME).exists());
    drop(r);
    let r2 = ReferenceDeployment::open_for_recovery(
        &d,
        RecoveryAction::TruncateIncompleteLedgerTail,
        &cx,
    );
    assert!(matches!(r2, Err(ReferenceError::NoIncompleteTail { .. })));
    let d2 = tdir("p06b");
    fs::create_dir_all(&d2)?;
    fs::write(
        d2.join("LAYOUT.tmp.12345"),
        b"schema=fss.reference_deployment.layout.v1\nvers",
    )?;
    let r3 = ReferenceDeployment::open(&d2, "site:p06", &cx);
    assert!(
        r3.is_ok(),
        "open with stale LAYOUT.tmp must succeed: {r3:?}"
    );
    assert!(
        !d2.join("LAYOUT.tmp.12345").exists(),
        "stale LAYOUT.tmp must be removed"
    );
    assert!(d2.join(DEPLOYMENT_LAYOUT_FILENAME).exists());
    drop(r3);
    let _ = fs::remove_dir_all(&d);
    let _ = fs::remove_dir_all(&d2);
    Ok(())
}

#[test]
fn p07_torn_layout() -> R {
    let d = tdir("p07");
    let cx = test_cx("p07")?;
    drop(ReferenceDeployment::open(&d, "site:p07", &cx)?);
    let lay = d.join(DEPLOYMENT_LAYOUT_FILENAME);
    let t = fs::read(&lay)?;
    fs::write(&lay, &t[..t.len() / 2])?;
    let r = ReferenceDeployment::open(&d, "site:p07", &cx);
    assert!(
        matches!(
            r,
            Err(ReferenceError::InvalidSpec("missing layout effects"))
        ),
        "torn LAYOUT must be refused as missing its effects key: {r:?}"
    );
    let _ = fs::remove_dir_all(&d);
    Ok(())
}

#[test]
fn p08_layout_relpaths_not_validated() -> R {
    let d = tdir("p08");
    let cx = test_cx("p08")?;
    drop(ReferenceDeployment::open(&d, "site:p08", &cx)?);
    let lay = d.join(DEPLOYMENT_LAYOUT_FILENAME);
    let t = fs::read_to_string(&lay)?;
    let t2 = t.replace(
        "ledger=ledger/journal.fssj",
        "ledger=../elsewhere/evil.fssj",
    ) + "unknown_key=zzz\nschema: fss.reference_deployment.layout.v1\n";
    fs::write(&lay, &t2)?;
    let r = ReferenceDeployment::open(&d, "site:p08", &cx);
    assert!(
        matches!(
            r,
            Err(ReferenceError::InvalidSpec("invalid layout ledger relpath"))
        ),
        "escaping ledger relpath must be refused: {r:?}"
    );
    // Also test L3 directly: wrong relpath must fail
    let t3 = t.replace("ledger=ledger/journal.fssj", "ledger=ledger/wrong.fssj");
    let parsed = DeploymentLayout::parse_canonical_text(&t3);
    assert!(
        matches!(
            parsed,
            Err(ReferenceError::InvalidSpec("invalid layout ledger relpath"))
        ),
        "expected invalid layout ledger relpath, got: {parsed:?}"
    );
    let _ = fs::remove_dir_all(&d);
    Ok(())
}

#[test]
fn p09_lineage_validation_before_layout_write() -> R {
    let cx = test_cx("p09")?;
    for (tag, lin, reason) in [
        (
            "p09a",
            "site:a\nschema=evil",
            "deployment site_lineage contains whitespace or control characters",
        ),
        ("p09b", "", "deployment site_lineage is empty"),
        (
            "p09c",
            "has space",
            "deployment site_lineage contains whitespace or control characters",
        ),
    ] {
        let d = tdir(tag);
        let r = ReferenceDeployment::open(&d, lin, &cx);
        match r {
            Err(ReferenceError::InvalidSpec(got)) => assert_eq!(got, reason, "{lin:?}"),
            other => {
                return Err(format!("lineage {lin:?}: expected InvalidSpec, got {other:?}").into());
            }
        }
        assert!(
            !d.join(DEPLOYMENT_LAYOUT_FILENAME).exists(),
            "LAYOUT must not be written on invalid lineage"
        );
        let _ = fs::remove_dir_all(&d);
    }
    Ok(())
}

#[test]
fn p10_recovery_on_healthy_root_changes_nothing() -> R {
    let d = tdir("p10");
    let cx = test_cx("p10")?;
    {
        let mut dep = ReferenceDeployment::open(&d, "site:p10", &cx)?;
        let slot = SlotName::parse("slot-p10")?;
        let p = dep.stage_payload(b"p10")?;
        let m = ObjectManifest::new("slot-p10", [p], None)?;
        dep.publish_and_commit(&slot, &m, iv(1, 2)?, &cx)?;
    }
    let lp = d.join("ledger/journal.fssj");
    let ep = d.join("effects/journal.fssj");
    let snap = (fs::read(&lp)?, fs::read(&ep)?, fs::read(d.join("LAYOUT"))?);
    let e = err_of(ReferenceDeployment::open_for_recovery(
        &d,
        RecoveryAction::TruncateIncompleteLedgerTail,
        &cx,
    ))?;
    println!("PROBE p10 truncate ledger on healthy: {e:?}");
    assert!(matches!(&e, ReferenceError::NoIncompleteTail { path } if path == &lp));
    let e = err_of(ReferenceDeployment::open_for_recovery(
        &d,
        RecoveryAction::TruncateIncompleteEffectTail,
        &cx,
    ))?;
    println!("PROBE p10 truncate effects on healthy: {e:?}");
    assert!(matches!(&e, ReferenceError::NoIncompleteTail { path } if path == &ep));
    let e = err_of(ReferenceDeployment::open_for_recovery(
        &d,
        RecoveryAction::ApplySealedLedgerRepair {
            plan_digest: ContentDigest::sha256(b"x"),
        },
        &cx,
    ))?;
    println!("PROBE p10 sealed repair on healthy: {e:?}");
    assert_eq!(
        snap,
        (fs::read(&lp)?, fs::read(&ep)?, fs::read(d.join("LAYOUT"))?)
    );
    let m = tdir("p10missing");
    let e = err_of(ReferenceDeployment::open_for_recovery(
        &m,
        RecoveryAction::TruncateIncompleteLedgerTail,
        &cx,
    ))?;
    println!("PROBE p10 missing root: {e:?}; created={}", m.exists());
    assert!(matches!(e, ReferenceError::NotADeployment { .. }));
    assert!(!m.exists());
    let o = tdir("p10layoutonly");
    fs::create_dir_all(&o)?;
    fs::copy(d.join("LAYOUT"), o.join("LAYOUT"))?;
    let r = ReferenceDeployment::open_for_recovery(
        &o,
        RecoveryAction::TruncateIncompleteLedgerTail,
        &cx,
    );
    match r {
        Err(ReferenceError::NotADeployment { path }) => assert_eq!(path, o),
        other => {
            return Err(
                format!("p10 LAYOUT-only root: expected NotADeployment, got {other:?}").into(),
            );
        }
    }
    assert_eq!(
        listing(&o),
        vec!["LAYOUT"],
        "recovery must not create objects/"
    );
    let _ = fs::remove_dir_all(&d);
    let _ = fs::remove_dir_all(&o);
    Ok(())
}

#[test]
fn p11_effect_tail_typed_and_recoverable() -> R {
    let d = tdir("p11");
    let cx = test_cx("p11")?;
    drop(ReferenceDeployment::open(&d, "site:p11", &cx)?);
    let ep = d.join("effects/journal.fssj");
    append_raw(&ep, b"FSSJRN01\x00\x01torn-effect")?;
    let e = err_of(ReferenceDeployment::open(&d, "site:p11", &cx))?;
    println!("PROBE p11 effect tail: {e:?}");
    match &e {
        ReferenceError::IncompleteJournalTail {
            path,
            next_affordance,
            offset,
        } => {
            assert_eq!(path, &ep);
            assert_eq!(
                next_affordance,
                &format!(
                    "fss-lab recover --root {} --truncate-effect-tail",
                    d.display()
                )
            );
            println!("PROBE p11 offset {offset}");
        }
        other => return Err(format!("p11 unexpected {other:?}").into()),
    }
    let rc = ReferenceDeployment::open_for_recovery(
        &d,
        RecoveryAction::TruncateIncompleteEffectTail,
        &cx,
    )?;
    println!("PROBE p11 receipt {rc:?}");
    assert!(matches!(
        rc,
        RecoveryReceipt::TruncatedEffectTail {
            truncated_bytes: 21,
            ..
        }
    ));
    drop(ReferenceDeployment::open(&d, "site:p11", &cx)?);
    let _ = fs::remove_dir_all(&d);
    Ok(())
}

#[test]
fn p12_plan_digest_mismatch_refused_untouched() -> R {
    let d = tdir("p12");
    let cx = test_cx("p12")?;
    drop(ReferenceDeployment::open(&d, "site:p12", &cx)?);
    let lp = d.join("ledger/journal.fssj");
    append_raw(&lp, b"garbage-without-record-magic-000000")?;
    let before = fs::read(&lp)?;
    let plan = doctor_path(&lp)?.plan(&lp)?;
    let wrong = ContentDigest::sha256(b"wrong");
    let e = err_of(ReferenceDeployment::open_for_recovery(
        &d,
        RecoveryAction::ApplySealedLedgerRepair { plan_digest: wrong },
        &cx,
    ))?;
    println!("PROBE p12 {e:?}");
    match e {
        ReferenceError::PlanDigestMismatch { expected, actual } => {
            assert_eq!(expected, wrong);
            assert_eq!(actual, plan.plan_digest());
        }
        other => return Err(format!("p12 unexpected {other:?}").into()),
    }
    assert_eq!(before, fs::read(&lp)?);
    let _ = fs::remove_dir_all(&d);
    Ok(())
}

#[test]
fn p14_crash_after_root_durable() -> R {
    let d = tdir("p14");
    let cx = test_cx("p14")?;
    let slot = SlotName::parse("slot-p14")?;
    let m = {
        let mut dep = ReferenceDeployment::open(&d, "site:p14", &cx)?;
        let p = dep.stage_payload(b"p14")?;
        let m = ObjectManifest::new("slot-p14", [p], None)?;
        let mut lp = dep.ledgered_publisher();
        lp.inject_crash_at(LedgerCutPoint::AfterRootDurable);
        let r = lp.publish_and_commit(&slot, &m, iv(1, 2)?);
        println!("PROBE p14 injected -> {:?}", r.as_ref().err());
        m
    };
    let mut dep = ReferenceDeployment::open(&d, "site:p14", &cx)?;
    let rec = dep.reconcile()?;
    println!(
        "PROBE p14 reopen reconcile pending={} clean={}",
        rec.pending.len(),
        rec.is_clean()
    );
    assert_eq!(rec.pending.len(), 1);
    let rc = dep.publish_and_commit(&slot, &m, iv(1, 2)?, &cx)?;
    println!("PROBE p14 recommit outcome {:?}", rc.outcome);
    assert!(dep.reconcile()?.is_clean());
    drop(dep);
    let _ = fs::remove_dir_all(&d);
    Ok(())
}

fn alert_plan() -> Result<ReferenceAlertPlan, Box<dyn Error>> {
    let event_root = ContentDigest::sha256(b"event-root");
    let event_revision_digest = ContentDigest::sha256(b"rev-digest");
    let channel = "simulated-channel".to_owned();
    let mut req = fss_core::CanonicalEncoder::new();
    req.text("fss.reference_alert_request.v1");
    req.digest(event_root);
    req.digest(event_revision_digest);
    req.text(&channel);
    Ok(ReferenceAlertPlan {
        intent: fss_core::EffectIntent {
            operation_id: OperationId::parse("op:alert:p15")?,
            idempotency_key: fss_core::IdempotencyKey::parse("idemp:alert:p15")?,
            effect_class: "alert.dispatch".to_owned(),
            request_digest: ContentDigest::sha256(&req.finish()),
            precondition_digest: ContentDigest::sha256(b"alert-pre"),
        },
        obligation_id: fss_core::ObligationId::parse("ob:alert:p15")?,
        event_root,
        event_revision_digest,
        authority_anchor: fss_core::LedgerAnchor::genesis("site:p15"),
        channel,
        // Inert sealed-dispatch fields: this plan is only ever offered to a cancelled context,
        // which refuses before any revalidation reads them.
        event_revision_encoding: Vec::new(),
        prepared_head_sequence: 0,
        prepared_head_digest: ContentDigest::sha256(b"p15-no-head"),
        prior_revision_encodings: Vec::new(),
    })
}

#[test]
fn p15_cancellation_matrix() -> R {
    let d = tdir("p15");
    let c = test_cx("p15-cancel")?;
    c.request_cancellation();
    let e = err_of(ReferenceDeployment::open(&d, "site:p15", &c))?;
    println!("PROBE p15 open: {e:?}; root created={}", d.exists());
    assert!(matches!(
        e,
        ReferenceError::CancellationRequested {
            stage: "deployment_open"
        }
    ));
    assert!(!d.exists());
    let ok = test_cx("p15-ok")?;
    let mut dep = ReferenceDeployment::open(&d, "site:p15", &ok)?;
    let lj = fs::read(d.join("ledger/journal.fssj"))?;
    let slot = SlotName::parse("slot-p15")?;
    let e = err_of(dep.stage_and_publish(&slot, &[b"x"], &c))?;
    println!("PROBE p15 stage_and_publish: {e:?}");
    assert!(matches!(
        e,
        ReferenceError::CancellationRequested {
            stage: "stage_objects"
        }
    ));
    let p = dep.stage_payload(b"p15")?;
    let m = ObjectManifest::new("slot-p15", [p], None)?;
    let e = err_of(dep.publish_and_commit(&slot, &m, iv(1, 2)?, &c))?;
    println!("PROBE p15 publish_and_commit: {e:?}");
    assert!(matches!(
        e,
        ReferenceError::CancellationRequested {
            stage: "publish_root"
        }
    ));
    let e = err_of(dep.append_batch(
        BatchId::parse("batch:authority:p15")?,
        vec![delta("delta:p15", "object:p15", p)?],
        vec![p],
        &c,
    ))?;
    println!("PROBE p15 append_batch: {e:?}");
    assert!(matches!(
        e,
        ReferenceError::CancellationRequested {
            stage: "append_batch"
        }
    ));
    let e = err_of(dep.evaluate_policy(EventId::parse("event:p15")?, vec![], &c))?;
    println!("PROBE p15 evaluate_policy: {e:?}");
    assert!(matches!(
        e,
        ReferenceError::CancellationRequested {
            stage: "evaluate_policy"
        }
    ));
    let plan = alert_plan()?;
    let e = err_of(dep.dispatch_alert(
        &plan,
        ReferenceProviderBehavior::Deliver,
        TimestampNs(1),
        TimestampNs(2),
        &c,
    ))?;
    println!("PROBE p15 dispatch_alert: {e:?}");
    assert!(matches!(
        e,
        ReferenceError::CancellationRequested {
            stage: "dispatch_alert"
        }
    ));
    assert_eq!(lj, fs::read(d.join("ledger/journal.fssj"))?);
    assert_eq!(dep.alert_provider().message_count(), 0);
    drop(dep);
    let e = err_of(ReferenceDeployment::open_for_recovery(
        &d,
        RecoveryAction::TruncateIncompleteLedgerTail,
        &c,
    ))?;
    println!("PROBE p15 open_for_recovery: {e:?}");
    assert!(matches!(
        e,
        ReferenceError::CancellationRequested {
            stage: "deployment_open"
        }
    ));
    let _ = fs::remove_dir_all(&d);
    Ok(())
}

#[test]
fn p16_root_kinds() -> R {
    use std::os::unix::fs::PermissionsExt;
    let cx = test_cx("p16")?;
    let f = tdir("p16file");
    fs::write(&f, b"i am a file")?;
    let r = ReferenceDeployment::open(&f, "site:p16", &cx);
    assert!(
        matches!(&r, Err(ReferenceError::NotADeployment { path }) if path == &f),
        "{r:?}"
    );
    let _ = fs::remove_file(&f);

    let real = tdir("p16real");
    fs::create_dir_all(&real)?;
    let link = tdir("p16link");
    std::os::unix::fs::symlink(&real, &link)?;
    let r = ReferenceDeployment::open(&link, "site:p16", &cx);
    assert!(r.is_ok(), "symlink to empty dir must succeed: {r:?}");
    drop(r);
    let _ = fs::remove_file(&link);
    let _ = fs::remove_dir_all(&real);

    let dangling = tdir("p16dangling");
    std::os::unix::fs::symlink(tdir("p16nowhere"), &dangling)?;
    let r = ReferenceDeployment::open(&dangling, "site:p16", &cx);
    assert!(
        matches!(&r, Err(ReferenceError::NotADeployment { path }) if path == &dangling),
        "dangling symlink must be refused as not a deployment: {r:?}"
    );
    assert!(
        fs::symlink_metadata(tdir("p16nowhere")).is_err(),
        "a refused dangling symlink must not create its target"
    );
    let _ = fs::remove_file(&dangling);
    let _ = fs::remove_dir_all(tdir("p16nowhere"));

    let ro = tdir("p16ro");
    fs::create_dir_all(&ro)?;
    let enforced = permission_bits_enforced(&ro)?;
    fs::set_permissions(&ro, fs::Permissions::from_mode(0o555))?;
    let r = ReferenceDeployment::open(&ro, "site:p16", &cx);
    fs::set_permissions(&ro, fs::Permissions::from_mode(0o755))?;
    if enforced {
        assert!(
            matches!(&r, Err(ReferenceError::Io(e)) if e.kind() == io::ErrorKind::PermissionDenied),
            "read-only dir must fail with PermissionDenied: {r:?}"
        );
    } else {
        eprintln!(
            "p16: permission bits are not enforced for this process; read-only branch not observable"
        );
        assert!(
            r.is_ok(),
            "a privileged open of an empty dir succeeds: {r:?}"
        );
    }
    drop(r);
    let _ = fs::remove_dir_all(&ro);

    let rel = PathBuf::from(format!("refdep-recovery-rel-{}", std::process::id()));
    let r = ReferenceDeployment::open(&rel, "site:p16", &cx);
    assert!(r.is_ok(), "relative root must succeed: {r:?}");
    drop(r);
    let _ = fs::remove_dir_all(&rel);
    Ok(())
}

#[test]
fn p17_stage_and_publish_bypasses_ledger() -> R {
    let d = tdir("p17");
    let cx = test_cx("p17")?;
    let mut dep = ReferenceDeployment::open(&d, "site:p17", &cx)?;
    let slot = SlotName::parse("slot-p17")?;
    let handle = dep.stage_and_publish(&slot, &[b"p17-a"], &cx)?;
    assert_eq!(handle.slot, slot);
    // Stage-only: the slot reports a staged manifest and nothing is visible.
    assert_eq!(
        dep.publisher().root(&slot).map(|root| root.state),
        Some(LocalPublicationState::Staged)
    );
    assert_eq!(dep.publisher().visible_roots().count(), 0);
    let rec = dep.reconcile()?;
    assert_eq!(rec.ledgered.len(), 0);
    assert_eq!(rec.pending.len(), 0);
    assert!(rec.is_clean());
    assert!(dep.ledger().batches().is_empty());
    drop(dep);
    // Staging that was never published surfaces on reopen as unreferenced custody: the child and
    // the staged manifest body.
    let dep = ReferenceDeployment::open(&d, "site:p17", &cx)?;
    let mut expected = vec![ContentDigest::sha256(b"p17-a"), handle.root];
    expected.sort();
    assert_eq!(dep.recovery_report().unreferenced_objects, expected);
    assert!(!dep.recovery_report().is_clean());
    assert!(dep.publisher().root(&slot).is_none());
    drop(dep);
    let _ = fs::remove_dir_all(&d);
    Ok(())
}

#[test]
fn p18_orphan_staging_surfaces_on_reopen() -> R {
    let d = tdir("p18");
    let cx = test_cx("p18")?;
    let p = {
        let mut dep = ReferenceDeployment::open(&d, "site:p18", &cx)?;
        dep.stage_payload(b"orphan")?
    };
    let dep = ReferenceDeployment::open(&d, "site:p18", &cx)?;
    assert_eq!(dep.recovery_report().unreferenced_objects, vec![p]);
    assert!(!dep.recovery_report().is_clean());
    drop(dep);
    let _ = fs::remove_dir_all(&d);
    Ok(())
}

#[test]
fn p19_children_order_idempotency() -> R {
    let d = tdir("p19");
    let cx = test_cx("p19")?;
    let mut dep = ReferenceDeployment::open(&d, "site:p19", &cx)?;
    let a = dep.stage_payload(b"p19-a")?;
    let b = dep.stage_payload(b"p19-b")?;
    let (hi, lo) = if a > b { (a, b) } else { (b, a) };
    let bid = BatchId::parse("batch:authority:p19")?;
    let dl1 = delta("delta:p19:1", "object:p19:1", lo)?;
    let dl2 = delta("delta:p19:2", "object:p19:2", hi)?;
    let r1 = dep.append_batch(
        bid.clone(),
        vec![dl2.clone(), dl1.clone()],
        vec![hi, lo, hi],
        &cx,
    );
    assert!(r1.is_ok(), "append_batch must succeed: {r1:?}");
    let stored = &dep.ledger().batches()[0];
    assert_eq!(stored.children, vec![lo, hi]);
    assert_eq!(stored.deltas[0].delta_id, dl1.delta_id);
    assert_eq!(stored.deltas[1].delta_id, dl2.delta_id);
    let r2 = dep.append_batch(bid, vec![dl2, dl1], vec![hi, lo, hi], &cx);
    assert!(
        r2.is_ok(),
        "identical retry must succeed without BatchIdConflict"
    );
    drop(dep);
    let _ = fs::remove_dir_all(&d);
    Ok(())
}

#[test]
fn p20_capacity_refusals() -> R {
    let cx = test_cx("p20")?;
    let d = tdir("p20a");
    let lim = DeploymentLimits {
        manifest_children_max: 1,
        batch_entries_max: 1,
        spool_total_max_bytes: 10,
        ..DeploymentLimits::standard()
    };
    let mut dep = ReferenceDeployment::open_with_limits(&d, "site:p20", lim, &cx)?;
    let slot = SlotName::parse("slot-p20")?;
    let e = err_of(dep.stage_and_publish(&slot, &[b"a", b"b"], &cx))?;
    assert!(matches!(
        e,
        ReferenceError::CapacityExceeded {
            limit: "manifest_children_max",
            maximum: 1,
            actual: 2
        }
    ));
    let p = dep.stage_payload(b"12345678")?;
    let e = err_of(dep.append_batch(
        BatchId::parse("batch:authority:p20")?,
        vec![
            delta("delta:1", "object:1", p)?,
            delta("delta:2", "object:2", p)?,
        ],
        vec![p],
        &cx,
    ))?;
    assert!(matches!(
        e,
        ReferenceError::CapacityExceeded {
            limit: "batch_entries_max",
            maximum: 1,
            actual: 2
        }
    ));
    let r = dep.stage_payload(b"abcdefgh");
    assert!(matches!(
        r,
        Err(ReferenceError::CapacityExceeded {
            limit: "spool_total_max_bytes",
            ..
        })
    ));
    drop(dep);
    let _ = fs::remove_dir_all(&d);
    Ok(())
}

/// A [`LayoutIo`] that fails the rename, the directory fsync, or neither, with a given kind.
struct InjectedLayoutIo {
    rename: Option<io::ErrorKind>,
    sync_dir: Option<io::ErrorKind>,
}

impl LayoutIo for InjectedLayoutIo {
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        match self.rename {
            Some(kind) => Err(io::Error::from(kind)),
            None => HostLayoutIo.rename(from, to),
        }
    }

    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        match self.sync_dir {
            Some(kind) => Err(io::Error::from(kind)),
            None => HostLayoutIo.sync_dir(dir),
        }
    }
}

#[test]
fn test_m4_atomic_layout_failure_preserves_previous_layout() -> R {
    let d = tdir("m4-atomic");
    let cx = test_cx("m4")?;
    let dep = ReferenceDeployment::open(&d, "site:m4:orig", &cx)?;
    let orig_layout = dep.layout_report().clone();
    drop(dep);
    let orig_text = fs::read_to_string(d.join(DEPLOYMENT_LAYOUT_FILENAME))?;

    let new_layout =
        DeploymentLayout::new("site:m4:mutated", ContentDigest::sha256(b"mutated-limits"));
    let failing_rename = InjectedLayoutIo {
        rename: Some(io::ErrorKind::StorageFull),
        sync_dir: None,
    };
    let res = write_layout_atomic(&d, &new_layout, &failing_rename);
    assert!(
        matches!(&res, Err(ReferenceError::Io(e)) if e.kind() == io::ErrorKind::StorageFull),
        "the injected rename failure must propagate: {res:?}"
    );
    let current_text = fs::read_to_string(d.join(DEPLOYMENT_LAYOUT_FILENAME))?;
    assert_eq!(
        current_text, orig_text,
        "atomic write failure must preserve original layout"
    );
    assert_eq!(
        DeploymentLayout::parse_canonical_text(&current_text)?,
        orig_layout
    );
    let temp_name = format!("{DEPLOYMENT_LAYOUT_FILENAME}.tmp.{}", std::process::id());
    assert_eq!(
        listing(&d),
        vec![
            DEPLOYMENT_LAYOUT_FILENAME.to_owned(),
            temp_name,
            "effects".to_owned(),
            "ledger".to_owned(),
            "objects".to_owned()
        ]
    );

    // The next open removes the stale temporary under the lock and keeps the original layout.
    drop(ReferenceDeployment::open(&d, "site:m4:orig", &cx)?);
    assert_eq!(listing(&d), vec!["LAYOUT", "effects", "ledger", "objects"]);
    assert_eq!(
        fs::read_to_string(d.join(DEPLOYMENT_LAYOUT_FILENAME))?,
        orig_text
    );
    let _ = fs::remove_dir_all(&d);
    Ok(())
}

#[test]
fn test_f3_injected_directory_fsync_failure_propagates_after_rename() -> R {
    let d = tdir("f3-injected");
    fs::create_dir_all(&d)?;
    let layout = DeploymentLayout::new("site:f3:test", ContentDigest::sha256(b"f3-limits"));
    let failing_sync = InjectedLayoutIo {
        rename: None,
        sync_dir: Some(io::ErrorKind::StorageFull),
    };
    let res = write_layout_atomic(&d, &layout, &failing_sync);
    assert!(
        matches!(&res, Err(ReferenceError::Io(e)) if e.kind() == io::ErrorKind::StorageFull),
        "the injected directory fsync failure must propagate: {res:?}"
    );
    // The rename happened, so the descriptor is visible, but its durability was not proven and
    // the write was reported as failed.
    assert_eq!(
        fs::read_to_string(d.join(DEPLOYMENT_LAYOUT_FILENAME))?,
        layout.to_canonical_text()
    );
    let _ = fs::remove_dir_all(&d);
    Ok(())
}

#[test]
fn test_f3_directory_fsync_error_propagation() -> R {
    use std::os::unix::fs::PermissionsExt;
    let d = tdir("f3-fsync");
    fs::create_dir_all(&d)?;
    let enforced = permission_bits_enforced(&d)?;
    let layout = DeploymentLayout::new("site:f3:test", ContentDigest::sha256(b"f3-limits"));
    fs::set_permissions(&d, fs::Permissions::from_mode(0o333))?;
    let res = write_layout_atomic(&d, &layout, &HostLayoutIo);
    fs::set_permissions(&d, fs::Permissions::from_mode(0o755))?;
    if enforced {
        assert!(
            matches!(&res, Err(ReferenceError::Io(e)) if e.kind() == io::ErrorKind::PermissionDenied),
            "write_layout_atomic must fail if directory fsync cannot be opened: {res:?}"
        );
    } else {
        // The deterministic injected-failure test covers this path on a privileged runner.
        eprintln!("f3: permission bits are not enforced for this process; see the injected test");
        assert!(res.is_ok(), "{res:?}");
    }
    let _ = fs::remove_dir_all(&d);
    Ok(())
}

#[test]
fn test_l2_duplicate_layout_key_refused() -> R {
    let text = format!(
        "schema={}\nversion={}\nsite_lineage=site:first\nsite_lineage=site:second\nledger=ledger/journal.fssj\nobjects=objects\neffects=effects/journal.fssj\nlimits_digest=sha256:0000000000000000000000000000000000000000000000000000000000000000\n",
        fss_reference::DEPLOYMENT_LAYOUT_SCHEMA,
        fss_reference::DEPLOYMENT_LAYOUT_FORMAT_VERSION,
    );
    let err = DeploymentLayout::parse_canonical_text(&text);
    assert!(
        matches!(
            err,
            Err(ReferenceError::InvalidSpec(
                "duplicate layout key: site_lineage"
            ))
        ),
        "expected duplicate layout key: site_lineage, got: {err:?}"
    );
    Ok(())
}

#[test]
fn test_k3_ledger_incomplete_tail_truncation_receipt_and_file_length() -> R {
    let d = tdir("k3-ledger-trunc");
    let cx = test_cx("k3")?;
    let mut dep = ReferenceDeployment::open(&d, "site:k3", &cx)?;
    let p = dep.stage_payload(b"k3-payload")?;
    let m = ObjectManifest::new("slot-k3", [p], None)?;
    dep.publish_and_commit(&SlotName::parse("slot-k3")?, &m, iv(1, 2)?, &cx)?;
    drop(dep);

    let ledger_path = d.join("ledger/journal.fssj");
    let committed_len = fs::metadata(&ledger_path)?.len();
    append_raw(&ledger_path, b"FSSJRN01\x00\x01torn-ledger-tail-bytes")?;
    let total_len = fs::metadata(&ledger_path)?.len();
    assert!(total_len > committed_len);

    let receipt = ReferenceDeployment::open_for_recovery(
        &d,
        RecoveryAction::TruncateIncompleteLedgerTail,
        &cx,
    )?;
    match receipt {
        RecoveryReceipt::TruncatedLedgerTail {
            path,
            committed_len: rec_committed,
            truncated_bytes,
            ..
        } => {
            assert_eq!(path, ledger_path);
            assert_eq!(rec_committed, committed_len);
            assert_eq!(truncated_bytes, total_len - committed_len);
        }
        other => return Err(format!("unexpected receipt: {other:?}").into()),
    }
    let actual_len = fs::metadata(&ledger_path)?.len();
    assert_eq!(
        actual_len, committed_len,
        "ledger file must be truncated to committed length"
    );
    let dep2 = ReferenceDeployment::open(&d, "site:k3", &cx)?;
    assert_eq!(dep2.site_lineage(), "site:k3");
    drop(dep2);
    let _ = fs::remove_dir_all(&d);
    Ok(())
}

#[test]
fn test_k4_effect_incomplete_tail_truncation_receipt_and_file_length() -> R {
    let d = tdir("k4-effect-trunc");
    let cx = test_cx("k4")?;
    let dep = ReferenceDeployment::open(&d, "site:k4", &cx)?;
    drop(dep);

    let effect_path = d.join("effects/journal.fssj");
    let committed_len = fs::metadata(&effect_path)?.len();
    append_raw(&effect_path, b"FSSJRN01\x00\x01torn-effect-tail-bytes")?;
    let total_len = fs::metadata(&effect_path)?.len();
    assert!(total_len > committed_len);

    let receipt = ReferenceDeployment::open_for_recovery(
        &d,
        RecoveryAction::TruncateIncompleteEffectTail,
        &cx,
    )?;
    match receipt {
        RecoveryReceipt::TruncatedEffectTail {
            path,
            committed_len: rec_committed,
            truncated_bytes,
            ..
        } => {
            assert_eq!(path, effect_path);
            assert_eq!(rec_committed, committed_len);
            assert_eq!(truncated_bytes, total_len - committed_len);
        }
        other => return Err(format!("unexpected receipt: {other:?}").into()),
    }
    let actual_len = fs::metadata(&effect_path)?.len();
    assert_eq!(
        actual_len, committed_len,
        "effect file must be truncated to committed length"
    );
    let dep2 = ReferenceDeployment::open(&d, "site:k4", &cx)?;
    assert_eq!(dep2.site_lineage(), "site:k4");
    drop(dep2);
    let _ = fs::remove_dir_all(&d);
    Ok(())
}

#[test]
fn test_symlink_lock_refused_in_recovery() -> R {
    let d = tdir("symlink-lock");
    let cx = test_cx("symlink-lock")?;
    let dep = ReferenceDeployment::open(&d, "site:symlock", &cx)?;
    drop(dep);

    let lock_path = d.join("objects/LOCK");
    let target_file = d.join("objects/target_for_link");
    fs::write(&target_file, b"lock-target")?;
    fs::remove_file(&lock_path)?;
    std::os::unix::fs::symlink(&target_file, &lock_path)?;

    let err = ReferenceDeployment::open_for_recovery(
        &d,
        RecoveryAction::TruncateIncompleteLedgerTail,
        &cx,
    );
    match err {
        Err(ReferenceError::LocalPublication(e)) => {
            assert!(
                matches!(
                    *e,
                    fss_publication::LocalPublicationError::InvalidLayout { .. }
                ),
                "expected InvalidLayout for symlinked lock, got: {e:?}"
            );
        }
        other => {
            return Err(format!("expected LocalPublication(InvalidLayout), got: {other:?}").into());
        }
    }
    let _ = fs::remove_dir_all(&d);
    Ok(())
}

#[test]
fn test_cancellation_c04_c09_c11_c12() -> R {
    let d = tdir("c04-c12");
    let ok_cx = test_cx("c04-c12-ok")?;
    let mut dep = ReferenceDeployment::open(&d, "site:cancel-more", &ok_cx)?;

    // C04: a context cancelled before the call refuses at the entry check (`stage_objects`),
    // even with no objects; the in-crate test `cancel_at_stage_manifest_fires_after_children_
    // are_staged` arms the later `stage_manifest` check.
    let cancel_cx = test_cx("c04-cancel")?;
    cancel_cx.request_cancellation();
    let slot = SlotName::parse("slot-c04")?;
    let err = dep.stage_and_publish(&slot, &[], &cancel_cx);
    assert!(
        matches!(
            err,
            Err(ReferenceError::CancellationRequested {
                stage: "stage_objects"
            })
        ),
        "expected stage_objects cancellation, got: {err:?}"
    );

    // C09: publish_event with cancelled cx cancels at publish_event
    let cancel_cx2 = test_cx("c09-cancel")?;
    cancel_cx2.request_cancellation();
    let decision = corroborated_decision(&mut dep, "event:c09", &ok_cx)?;
    let err = dep.publish_event(&decision, &cancel_cx2);
    assert!(
        matches!(
            err,
            Err(ReferenceError::CancellationRequested {
                stage: "publish_event"
            })
        ),
        "expected publish_event cancellation, got: {err:?}"
    );

    // Publish event for real so we can compile a situation
    let receipt = dep.publish_event(&decision, &ok_cx)?;
    let req = sample_situation_request(&decision, &receipt)?;

    // C11: compile_situation with cancelled cx cancels at compile_situation
    let cancel_cx3 = test_cx("c11-cancel")?;
    cancel_cx3.request_cancellation();
    let err = dep.compile_situation(req, &cancel_cx3);
    assert!(
        matches!(
            err,
            Err(ReferenceError::CancellationRequested {
                stage: "compile_situation"
            })
        ),
        "expected compile_situation cancellation, got: {err:?}"
    );

    // Compile situation for real
    let sit = dep.compile_situation(sample_situation_request(&decision, &receipt)?, &ok_cx)?;

    // C12: seal_handoff with cancelled cx cancels at seal_handoff
    let cancel_cx4 = test_cx("c12-cancel")?;
    cancel_cx4.request_cancellation();
    let handoff_id = HandoffId::parse("handoff:cancel:test")?;
    let err = dep.seal_handoff(
        &sit,
        handoff_id,
        TimestampNs(100),
        TimestampNs(200),
        &cancel_cx4,
    );
    assert!(
        matches!(
            err,
            Err(ReferenceError::CancellationRequested {
                stage: "seal_handoff"
            })
        ),
        "expected seal_handoff cancellation, got: {err:?}"
    );

    drop(dep);
    let _ = fs::remove_dir_all(&d);
    Ok(())
}

#[test]
fn test_publish_event_compile_situation_seal_handoff_lifecycle() -> R {
    let d = tdir("event-sit-handoff");
    let cx = test_cx("lifecycle")?;
    let mut dep = ReferenceDeployment::open(&d, "site:lifecycle", &cx)?;

    // 1. evaluate_policy + publish_event
    let decision = corroborated_decision(&mut dep, "event:life:1", &cx)?;
    let receipt = dep.publish_event(&decision, &cx)?;
    // The corroborating captures commit first; the event batch is the latest one.
    assert_eq!(&receipt.authority_anchor, dep.current_anchor());
    let event_batch = dep.ledger().batches().last().ok_or("no event batch")?;
    assert_eq!(event_batch.children, vec![receipt.event_root]);

    // 2. compile_situation
    let req = sample_situation_request(&decision, &receipt)?;
    let situation = dep.compile_situation(req, &cx)?;
    assert_eq!(
        situation.capsule.mission_id,
        MissionId::parse("mission:situation:test")?
    );
    assert_eq!(
        situation.capsule.session_id,
        SessionId::parse("session:situation:test")?
    );
    assert_eq!(situation.capsule.anchor, receipt.authority_anchor);

    // 3. seal_handoff
    let handoff_id = HandoffId::parse("handoff:lifecycle:1")?;
    let handoff = dep.seal_handoff(
        &situation,
        handoff_id,
        TimestampNs(1_000),
        TimestampNs(2_000),
        &cx,
    )?;
    assert_eq!(handoff.handoff_id.as_str(), "handoff:lifecycle:1");
    assert_eq!(handoff.mission_id, situation.capsule.mission_id);
    assert_eq!(handoff.anchor, receipt.authority_anchor);

    drop(dep);
    let _ = fs::remove_dir_all(&d);
    Ok(())
}

#[test]
fn test_typed_parameter_mismatch_errors() -> R {
    let d = tdir("mismatch-typed");
    let cx = test_cx("mismatch")?;
    let dep = ReferenceDeployment::open(&d, "site:original", &cx)?;
    drop(dep);

    // 1. Lineage mismatch
    let err = ReferenceDeployment::open(&d, "site:different", &cx);
    match err {
        Err(ReferenceError::SiteLineageMismatch { expected, actual }) => {
            assert_eq!(expected, "site:different");
            assert_eq!(actual, "site:original");
        }
        other => return Err(format!("expected SiteLineageMismatch, got: {other:?}").into()),
    }

    // 2. Limits digest mismatch
    let different_limits = DeploymentLimits {
        max_roots: 9999,
        ..DeploymentLimits::standard()
    };
    let expected_digest = different_limits.canonical_digest()?;
    let actual_digest = DeploymentLimits::standard().canonical_digest()?;
    let err2 = ReferenceDeployment::open_with_limits(&d, "site:original", different_limits, &cx);
    match err2 {
        Err(ReferenceError::LimitsDigestMismatch { expected, actual }) => {
            assert_eq!(expected, expected_digest);
            assert_eq!(actual, actual_digest);
        }
        other => return Err(format!("expected LimitsDigestMismatch, got: {other:?}").into()),
    }

    let _ = fs::remove_dir_all(&d);
    Ok(())
}

fn one_delta_batch(
    dep: &mut ReferenceDeployment,
) -> Result<(BatchId, EvidenceDelta, ContentDigest), Box<dyn Error>> {
    let p = dep.stage_payload(b"journal-bound-payload")?;
    let dl = delta("delta:bound:1", "object:bound:1", p)?;
    Ok((BatchId::parse("batch:authority:bound")?, dl, p))
}

/// The journal record bound is checked before `prepare_batch`: a batch whose record is exactly
/// `journal_record_max_bytes` long is accepted, one byte over is refused as `CapacityExceeded`,
/// and the refused append leaves the ledger journal byte-identical.
#[test]
fn journal_record_bound_admits_exactly_n_and_refuses_n_plus_one() -> R {
    let cx = test_cx("journal-bound")?;
    let probe_dir = tdir("journal-bound-probe");
    let record_len = {
        let mut dep = ReferenceDeployment::open(&probe_dir, "site:bound", &cx)?;
        let (bid, dl, p) = one_delta_batch(&mut dep)?;
        dep.append_batch(bid, vec![dl], vec![p], &cx)?;
        fss_ledger::encode_batch(&dep.ledger().batches()[0])?.len()
    };
    let exact = u32::try_from(record_len)?;

    let at_bound = tdir("journal-bound-exact");
    let lim = DeploymentLimits {
        journal_record_max_bytes: exact,
        ..DeploymentLimits::standard()
    };
    let mut dep = ReferenceDeployment::open_with_limits(&at_bound, "site:bound", lim, &cx)?;
    let (bid, dl, p) = one_delta_batch(&mut dep)?;
    let anchor = dep.append_batch(bid, vec![dl], vec![p], &cx)?;
    assert_eq!(anchor.commit_sequence, 1);
    assert_eq!(
        fss_ledger::encode_batch(&dep.ledger().batches()[0])?.len(),
        record_len
    );
    drop(dep);

    let over = tdir("journal-bound-over");
    let lim = DeploymentLimits {
        journal_record_max_bytes: exact - 1,
        ..DeploymentLimits::standard()
    };
    let mut dep = ReferenceDeployment::open_with_limits(&over, "site:bound", lim, &cx)?;
    let journal = over.join("ledger/journal.fssj");
    let before = fs::read(&journal)?;
    let (bid, dl, p) = one_delta_batch(&mut dep)?;
    let e = err_of(dep.append_batch(bid, vec![dl], vec![p], &cx))?;
    match e {
        ReferenceError::CapacityExceeded {
            limit,
            maximum,
            actual,
        } => {
            assert_eq!(limit, "journal_record_max_bytes");
            assert_eq!(maximum, u64::from(exact - 1));
            assert_eq!(actual, u64::from(exact));
        }
        other => return Err(format!("expected CapacityExceeded, got {other:?}").into()),
    }
    assert_eq!(
        fs::read(&journal)?,
        before,
        "a refused append must not touch the journal"
    );
    assert!(dep.ledger().batches().is_empty());
    drop(dep);
    for dir in [probe_dir, at_bound, over] {
        let _ = fs::remove_dir_all(&dir);
    }
    Ok(())
}

/// `batch_entries_max` admits exactly N deltas and exactly N children, and refuses N + 1
/// children (the delta side of N + 1 is covered by `p20_capacity_refusals`).
#[test]
fn batch_entries_bound_admits_exactly_n_deltas_and_children() -> R {
    let cx = test_cx("batch-entries")?;
    let d = tdir("batch-entries");
    let lim = DeploymentLimits {
        batch_entries_max: 2,
        ..DeploymentLimits::standard()
    };
    let mut dep = ReferenceDeployment::open_with_limits(&d, "site:entries", lim, &cx)?;
    let a = dep.stage_payload(b"entries-a")?;
    let b = dep.stage_payload(b"entries-b")?;
    let c = dep.stage_payload(b"entries-c")?;
    let anchor = dep.append_batch(
        BatchId::parse("batch:authority:entries:ok")?,
        vec![
            delta("delta:entries:1", "object:entries:1", a)?,
            delta("delta:entries:2", "object:entries:2", b)?,
        ],
        vec![a, b],
        &cx,
    )?;
    assert_eq!(anchor.commit_sequence, 1);
    let e = err_of(dep.append_batch(
        BatchId::parse("batch:authority:entries:over")?,
        vec![delta("delta:entries:3", "object:entries:3", c)?],
        vec![a, b, c],
        &cx,
    ))?;
    assert!(
        matches!(
            e,
            ReferenceError::CapacityExceeded {
                limit: "batch_entries_max",
                maximum: 2,
                actual: 3
            }
        ),
        "{e:?}"
    );
    assert_eq!(dep.ledger().batches().len(), 1);
    drop(dep);
    let _ = fs::remove_dir_all(&d);
    Ok(())
}

/// `manifest_children_max` admits a manifest with exactly N children.
#[test]
fn manifest_children_bound_admits_exactly_n() -> R {
    let cx = test_cx("manifest-children")?;
    let d = tdir("manifest-children");
    let lim = DeploymentLimits {
        manifest_children_max: 2,
        ..DeploymentLimits::standard()
    };
    let mut dep = ReferenceDeployment::open_with_limits(&d, "site:children", lim, &cx)?;
    let slot = SlotName::parse("slot-children")?;
    let handle = dep.stage_and_publish(&slot, &[b"child-a", b"child-b"], &cx)?;
    assert_eq!(handle.manifest.children().len(), 2);
    let receipt = dep.publish_and_commit(&slot, &handle.manifest, iv(1, 2)?, &cx)?;
    assert_eq!(receipt.root, handle.root);
    let e = err_of(dep.stage_and_publish(
        &SlotName::parse("slot-children-over")?,
        &[b"child-a", b"child-b", b"child-c"],
        &cx,
    ))?;
    assert!(
        matches!(
            e,
            ReferenceError::CapacityExceeded {
                limit: "manifest_children_max",
                maximum: 2,
                actual: 3
            }
        ),
        "{e:?}"
    );
    drop(dep);
    let _ = fs::remove_dir_all(&d);
    Ok(())
}

/// A crash injected at each publication cut point, then a reopen: the root state before and after
/// the reopen is exactly the expected one. A root is `Visible` right after the rename and becomes
/// `Durable` only when the reopen's recovery fsyncs the roots directory; it is never reported as
/// `Durable` before that. No cut point advances the ledger.
#[test]
fn reopen_after_crash_at_each_cut_point_reports_literal_root_state() -> R {
    let slot_name = "slot-cut";
    let cases = [
        (PublishCutPoint::AfterChildrenVerified, None, None, false),
        (PublishCutPoint::AfterManifestBody, None, None, false),
        (PublishCutPoint::AfterRootTempWrite, None, None, true),
        (
            PublishCutPoint::AfterRootRename,
            Some(LocalPublicationState::Visible),
            Some(LocalPublicationState::Durable),
            false,
        ),
    ];
    for (point, before_reopen, after_reopen, orphan_temp) in cases {
        let d = tdir(&format!("cut-{point}"));
        let cx = test_cx(&format!("cut-{point}"))?;
        let slot = SlotName::parse(slot_name)?;
        {
            let mut dep = ReferenceDeployment::open(&d, "site:cut", &cx)?;
            let p = dep.stage_payload(b"cut-point-payload")?;
            let m = ObjectManifest::new(slot_name, [p], None)?;
            dep.publisher_mut().inject_crash_at(point);
            let e = err_of(dep.publish_and_commit(&slot, &m, iv(1, 2)?, &cx))?;
            match e {
                ReferenceError::LocalPublication(boxed) => {
                    assert_eq!(*boxed, LocalPublicationError::InjectedCrash { point });
                }
                other => {
                    return Err(format!("{point}: expected InjectedCrash, got {other:?}").into());
                }
            }
            assert_eq!(
                dep.publisher().root(&slot).map(|root| root.state),
                before_reopen,
                "{point}: state before reopen"
            );
            assert!(dep.ledger().batches().is_empty(), "{point}");
        }
        let mut dep = ReferenceDeployment::open(&d, "site:cut", &cx)?;
        assert_eq!(
            dep.publisher().root(&slot).map(|root| root.state),
            after_reopen,
            "{point}: state after reopen"
        );
        assert!(dep.ledger().batches().is_empty(), "{point}");
        let expected_temps = if orphan_temp {
            vec![
                PathBuf::from(LOCAL_ROOTS_DIR)
                    .join(format!("{slot_name}{ROOT_RECORD_SUFFIX}{ROOT_TEMP_SUFFIX}")),
            ]
        } else {
            Vec::new()
        };
        assert_eq!(
            dep.recovery_report().orphaned_temps,
            expected_temps,
            "{point}"
        );
        let reconciliation = dep.reconcile()?;
        assert_eq!(
            reconciliation.pending.len(),
            usize::from(after_reopen.is_some()),
            "{point}: a durable unledgered root is pending, nothing else"
        );
        drop(dep);
        let _ = fs::remove_dir_all(&d);
    }
    Ok(())
}

/// An overfull roots directory is refused with the scan bound and a lower bound on its size.
#[test]
fn scan_limit_refusal_reports_a_lower_bound() -> R {
    let cx = test_cx("scan-limit")?;
    let d = tdir("scan-limit");
    let lim = DeploymentLimits {
        scan_max_objects: 8,
        max_roots: 8,
        max_tombstones: 8,
        spool_max_objects: 8,
        ..DeploymentLimits::standard()
    };
    drop(ReferenceDeployment::open_with_limits(
        &d,
        "site:scan",
        lim,
        &cx,
    )?);
    let roots = d.join("objects").join(LOCAL_ROOTS_DIR);
    for index in 0..12 {
        fs::write(roots.join(format!("junk-{index:02}")), b"x")?;
    }
    let e = err_of(ReferenceDeployment::open_with_limits(
        &d,
        "site:scan",
        lim,
        &cx,
    ))?;
    assert!(e.is_capacity_exceeded());
    match e {
        ReferenceError::ScanLimitExceeded {
            directory,
            maximum,
            at_least,
        } => {
            assert_eq!(directory, roots);
            assert_eq!(maximum, 8);
            assert_eq!(at_least, 9);
        }
        other => return Err(format!("expected ScanLimitExceeded, got {other:?}").into()),
    }
    let _ = fs::remove_dir_all(&d);
    Ok(())
}

/// Publishing the same decision again is an idempotent retry: it returns the receipt of the
/// committed revision, appends nothing, and leaves the ledger journal byte-identical.
#[test]
fn publish_event_retry_of_the_same_decision_is_idempotent() -> R {
    let d = tdir("event-idempotent");
    let cx = test_cx("event-idempotent")?;
    let mut dep = ReferenceDeployment::open(&d, "site:event-idempotent", &cx)?;
    let decision = corroborated_decision(&mut dep, "event:idempotent:1", &cx)?;
    let first = dep.publish_event(&decision, &cx)?;
    let batches = dep.ledger().batches().len();
    let journal = d.join("ledger/journal.fssj");
    let journal_bytes = fs::read(&journal)?;

    let retry = dep.publish_event(&decision, &cx)?;
    assert_eq!(retry.event_root, first.event_root);
    assert_eq!(retry.event_object_digest, first.event_object_digest);
    assert_eq!(retry.event_revision_digest, first.event_revision_digest);
    assert_eq!(retry.authority_anchor, first.authority_anchor);
    assert_eq!(
        retry.lineage_tamper_status.canonical_digest(),
        first.lineage_tamper_status.canonical_digest()
    );
    assert_eq!(
        retry.prior_revision_encodings,
        first.prior_revision_encodings
    );
    // The event batch witnesses the accumulated tamper status next to the revision.
    let event_batch = dep.ledger().batches().last().ok_or("no event batch")?;
    assert!(event_batch.deltas.iter().any(|delta| {
        delta.family == "sensor_tamper_status"
            && delta.payload_digest == first.event_root
            && delta.witness_digest == Some(first.lineage_tamper_status.canonical_digest())
    }));
    assert_eq!(
        dep.ledger().batches().len(),
        batches,
        "a retry appends nothing"
    );
    assert_eq!(fs::read(&journal)?, journal_bytes);
    assert_eq!(dep.current_anchor(), &first.authority_anchor);
    drop(dep);
    let _ = fs::remove_dir_all(&d);
    Ok(())
}

/// Exactly `scan_max_objects` entries in `roots/` open (non-root files are reported as foreign);
/// one more is refused with `at_least` = N + 1 (kills r9e N6).
#[test]
fn scan_bound_admits_exactly_n_root_entries_and_refuses_n_plus_one() -> R {
    let cx = test_cx("scan-exact")?;
    let d = tdir("scan-exact");
    let lim = DeploymentLimits {
        scan_max_objects: 8,
        max_roots: 8,
        max_tombstones: 8,
        spool_max_objects: 8,
        ..DeploymentLimits::standard()
    };
    drop(ReferenceDeployment::open_with_limits(
        &d,
        "site:scan-exact",
        lim,
        &cx,
    )?);
    let roots = d.join("objects").join(LOCAL_ROOTS_DIR);
    let mut expected = Vec::new();
    for index in 0..8 {
        let name = format!("junk-{index:02}");
        fs::write(roots.join(&name), b"x")?;
        expected.push(PathBuf::from(LOCAL_ROOTS_DIR).join(name));
    }
    let dep = ReferenceDeployment::open_with_limits(&d, "site:scan-exact", lim, &cx)?;
    assert_eq!(dep.recovery_report().foreign, expected);
    drop(dep);
    fs::write(roots.join("junk-08"), b"x")?;
    let e = err_of(ReferenceDeployment::open_with_limits(
        &d,
        "site:scan-exact",
        lim,
        &cx,
    ))?;
    match e {
        ReferenceError::ScanLimitExceeded {
            directory,
            maximum,
            at_least,
        } => {
            assert_eq!(directory, roots);
            assert_eq!(maximum, 8);
            assert_eq!(at_least, 9);
        }
        other => return Err(format!("expected ScanLimitExceeded at N + 1, got {other:?}").into()),
    }
    let _ = fs::remove_dir_all(&d);
    Ok(())
}
