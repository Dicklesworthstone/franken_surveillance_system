#![forbid(unsafe_code)]
//! Temporary adversarial probes (rcap9). Deleted after review.

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EventId, EvidenceDelta, ObjectId, OperationId, Plane,
    TimestampNs,
};
use fss_ledger::{AppendPhase, DurableLedgerError, doctor_path};
use fss_object::ObjectManifest;
use fss_publication::{LedgerCutPoint, SlotName};
use fss_reference::{
    DEPLOYMENT_LAYOUT_FILENAME, DeploymentLimits, RecoveryAction, RecoveryReceipt,
    ReferenceAlertPlan, ReferenceDeployment, ReferenceError, ReferenceProviderBehavior, ReplayCx,
};

type R = Result<(), Box<dyn Error>>;

fn tdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("fss-probe9-{tag}-{}", std::process::id()));
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
        .join(format!("test-replay-cx-probe9-{label}-{}", std::process::id()));
    let io = fss_reference::ReplayIoAuthority::from_context_authority(&root_auth, scratch_root)?;
    Ok(ReplayCx::new(io))
}

fn show<T>(r: &Result<T, ReferenceError>) -> String {
    match r {
        Ok(_) => "Ok".to_owned(),
        Err(e) => format!("Err({e:?})"),
    }
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
    println!("PROBE p05 lineage mismatch: {e:?}");
    assert!(
        matches!(
            e,
            ReferenceError::InvalidSpec("deployment site_lineage mismatch")
        ),
        "{e:?}"
    );
    let lim = DeploymentLimits {
        spool_object_max_bytes: 1024,
        ..DeploymentLimits::standard()
    };
    let e2 = err_of(ReferenceDeployment::open_with_limits(
        &d, "site:p05", lim, &cx,
    ))?;
    println!("PROBE p05 limits mismatch: {e2:?}");
    assert!(
        matches!(
            e2,
            ReferenceError::InvalidSpec("deployment limits_digest mismatch")
        ),
        "{e2:?}"
    );
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
    println!(
        "PROBE p06a skeleton (ledger/,objects/) no LAYOUT -> open: {}",
        show(&r)
    );
    drop(r);
    let r2 = ReferenceDeployment::open_for_recovery(
        &d,
        RecoveryAction::TruncateIncompleteLedgerTail,
        &cx,
    );
    println!("PROBE p06a -> open_for_recovery: {r2:?}");
    let d2 = tdir("p06b");
    fs::create_dir_all(&d2)?;
    fs::write(
        d2.join("LAYOUT.tmp.12345"),
        b"schema=fss.reference_deployment.layout.v1\nvers",
    )?;
    let r3 = ReferenceDeployment::open(&d2, "site:p06", &cx);
    println!("PROBE p06b stale LAYOUT.tmp only -> open: {}", show(&r3));
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
    println!("PROBE p07 torn LAYOUT -> open: {}", show(&r));
    assert!(r.is_err());
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
    fs::write(&lay, t2)?;
    match ReferenceDeployment::open(&d, "site:p08", &cx) {
        Ok(dep) => println!(
            "PROBE p08 tampered relpath ACCEPTED; layout_report.ledger_relpath={:?}",
            dep.layout_report().ledger_relpath
        ),
        Err(e) => println!("PROBE p08 tampered relpath refused: {e:?}"),
    }
    let _ = fs::remove_dir_all(&d);
    Ok(())
}

#[test]
fn p09_lineage_validation_before_layout_write() -> R {
    let cx = test_cx("p09")?;
    for (tag, lin) in [
        ("p09a", "site:a\nschema=evil"),
        ("p09b", ""),
        ("p09c", "has space"),
    ] {
        let d = tdir(tag);
        let r = ReferenceDeployment::open(&d, lin, &cx);
        println!(
            "PROBE {tag} lineage {lin:?} -> {} ; LAYOUT exists after: {}",
            show(&r),
            d.join("LAYOUT").exists()
        );
        drop(r);
        let r2 = ReferenceDeployment::open(&d, lin, &cx);
        println!("PROBE {tag} reopen -> {}", show(&r2));
        drop(r2);
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
    let snap = (
        fs::read(&lp)?,
        fs::read(&ep)?,
        fs::read(d.join("LAYOUT"))?,
    );
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
        (
            fs::read(&lp)?,
            fs::read(&ep)?,
            fs::read(d.join("LAYOUT"))?
        )
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
    println!(
        "PROBE p10 LAYOUT-only root recovery: {r:?}; listing after {:?}; objects/ listing {:?}",
        listing(&o),
        listing(&o.join("objects"))
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
fn p13_crash_injection_each_injectable_phase() -> R {
    let cx = test_cx("p13")?;
    for phase in [
        AppendPhase::BodyWrite,
        AppendPhase::BodySync,
        AppendPhase::CommitWrite,
        AppendPhase::CommitSync,
    ] {
        let d = tdir(&format!("p13-{phase:?}"));
        let bid = BatchId::parse("batch:authority:crash")?;
        let (dl, p) = {
            let mut dep = ReferenceDeployment::open(&d, "site:p13", &cx)?;
            let p = dep.stage_payload(b"crash-payload")?;
            let dl = delta("delta:crash:1", "object:crash:1", p)?;
            dep.ledger_mut().fail_journal_after_phase(phase);
            let r = dep.append_batch(bid.clone(), vec![dl.clone()], vec![p], &cx);
            println!("PROBE p13 {phase:?} append -> {}", show(&r));
            (dl, p)
        };
        let mut dep = match ReferenceDeployment::open(&d, "site:p13", &cx) {
            Ok(dep) => {
                println!(
                    "PROBE p13 {phase:?} reopen Ok; batches={}",
                    dep.ledger().batches().len()
                );
                dep
            }
            Err(e) => {
                println!("PROBE p13 {phase:?} reopen Err({e:?})");
                let rc = ReferenceDeployment::open_for_recovery(
                    &d,
                    RecoveryAction::TruncateIncompleteLedgerTail,
                    &cx,
                );
                println!("PROBE p13 {phase:?} recover -> {rc:?}");
                let dep = ReferenceDeployment::open(&d, "site:p13", &cx)?;
                println!(
                    "PROBE p13 {phase:?} reopen after recover; batches={}",
                    dep.ledger().batches().len()
                );
                dep
            }
        };
        let r = dep.append_batch(bid.clone(), vec![dl], vec![p], &cx)?;
        println!(
            "PROBE p13 {phase:?} retry -> commit_sequence {}; batches={}",
            r.commit_sequence,
            dep.ledger().batches().len()
        );
        assert_eq!(r.commit_sequence, 1);
        assert_eq!(dep.ledger().batches().len(), 1);
        let rec = dep.reconcile()?;
        println!(
            "PROBE p13 {phase:?} reconcile clean={} ; spool recovery clean={}",
            rec.is_clean(),
            dep.recovery_report().is_clean()
        );
        drop(dep);
        let _ = fs::remove_dir_all(&d);
    }
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
    println!("PROBE p16 root is file -> {}", show(&r));
    drop(r);
    let _ = fs::remove_file(&f);

    let real = tdir("p16real");
    fs::create_dir_all(&real)?;
    let link = tdir("p16link");
    std::os::unix::fs::symlink(&real, &link)?;
    let r = ReferenceDeployment::open(&link, "site:p16", &cx);
    println!(
        "PROBE p16 root is symlink to empty dir -> {} ; real listing {:?}",
        show(&r),
        listing(&real)
    );
    drop(r);
    let _ = fs::remove_file(&link);
    let _ = fs::remove_dir_all(&real);

    let dangling = tdir("p16dangling");
    std::os::unix::fs::symlink(tdir("p16nowhere"), &dangling)?;
    let r = ReferenceDeployment::open(&dangling, "site:p16", &cx);
    println!("PROBE p16 dangling symlink root -> {}", show(&r));
    drop(r);
    let _ = fs::remove_file(&dangling);
    let _ = fs::remove_dir_all(tdir("p16nowhere"));

    let ro = tdir("p16ro");
    fs::create_dir_all(&ro)?;
    fs::set_permissions(&ro, fs::Permissions::from_mode(0o555))?;
    let r = ReferenceDeployment::open(&ro, "site:p16", &cx);
    println!("PROBE p16 read-only empty dir -> {}", show(&r));
    drop(r);
    fs::set_permissions(&ro, fs::Permissions::from_mode(0o755))?;
    let _ = fs::remove_dir_all(&ro);

    let rel = PathBuf::from(format!("probe9-rel-{}", std::process::id()));
    let r = ReferenceDeployment::open(&rel, "site:p16", &cx);
    println!(
        "PROBE p16 relative root -> {} ; root()={:?}",
        show(&r),
        r.as_ref().map(|x| x.root().to_path_buf()).ok()
    );
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
    let receipt = dep.stage_and_publish(&slot, &[b"p17-a"], &cx)?;
    let seq = dep.current_anchor().commit_sequence;
    let rec = dep.reconcile()?;
    println!(
        "PROBE p17 after stage_and_publish: root={} anchor_seq={seq} ledgered={} pending={} clean={}",
        receipt.root,
        rec.ledgered.len(),
        rec.pending.len(),
        rec.is_clean()
    );
    drop(dep);
    let dep = ReferenceDeployment::open(&d, "site:p17", &cx)?;
    println!(
        "PROBE p17 reopen spool recovery clean={} unreferenced={}",
        dep.recovery_report().is_clean(),
        dep.recovery_report().unreferenced_objects.len()
    );
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
    println!(
        "PROBE p18 unreferenced={:?} clean={}",
        dep.recovery_report().unreferenced_objects,
        dep.recovery_report().is_clean()
    );
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
    let dl = delta("delta:p19", "object:p19", lo)?;
    let r1 = dep.append_batch(bid.clone(), vec![dl.clone()], vec![hi, lo], &cx);
    println!("PROBE p19 first (unsorted children) -> {}", show(&r1));
    if r1.is_ok() {
        let stored = dep.ledger().batches()[0].children.clone();
        println!(
            "PROBE p19 stored children order == offered: {}",
            stored == vec![hi, lo]
        );
        let r2 = dep.append_batch(bid, vec![dl], vec![hi, lo], &cx);
        println!("PROBE p19 identical retry -> {}", show(&r2));
        match r2 {
            Err(ReferenceError::DurableLedger(b))
                if matches!(*b, DurableLedgerError::BatchIdConflict { .. }) =>
            {
                return Err("identical retry refused as BatchIdConflict".into());
            }
            other => {
                other?;
            }
        }
    }
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
    println!("PROBE p20 children: {e:?}");
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
    println!("PROBE p20 deltas: {e:?}");
    assert!(matches!(
        e,
        ReferenceError::CapacityExceeded {
            limit: "batch_deltas_max",
            maximum: 1,
            actual: 2
        }
    ));
    let r = dep.stage_payload(b"abcdefgh");
    println!("PROBE p20 spool total (10 bytes, 16 requested) -> {}", show(&r));
    drop(dep);
    let _ = fs::remove_dir_all(&d);
    Ok(())
}
