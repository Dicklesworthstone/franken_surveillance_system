#![forbid(unsafe_code)]
//! Live owner admission reaches retained-source and publication boundaries.

use std::cell::{Cell, RefCell};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec,
    SensorId, TimestampNs,
};
use fss_publication::{PublishCancellation, PublishCutPoint};
use fss_reference::onvif::metadata::{RetainedMetadata, SourceBinding, retain};
use fss_reference::reference_deployment::{ReplayCancellationBridge, STAGE_AFTER_ROOT_TEMP_WRITE};
use fss_reference::{
    ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayAdapterError, ReplayAdmissionError, ReplayCx,
    ReplayIoAuthority, ScopedLedgerDir,
};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

struct Directory(PathBuf);

impl Directory {
    fn new() -> Test<Self> {
        for _ in 0..64 {
            let path = std::env::temp_dir().join(format!(
                "fss-replay-admission-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::SeqCst)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("fixture directory bound exhausted".into())
    }

    fn root(&self) -> PathBuf {
        self.0.join("deployment")
    }

    fn cx(&self) -> Test<ReplayCx> {
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:replay-admission".into(),
            operation_id: OperationId::parse("operation:replay-admission")?,
            principal: "operator:replay-admission".into(),
            capabilities: vec![ADP_REPLAY_ROW_ID.into()],
            deadline: None,
            priority: 1,
            budgets: BudgetVector::builder()
                .bytes(16 * 1024 * 1024)
                .storage_operations(4096)
                .build()?,
            privacy_scope: "privacy:fixture".into(),
            retention_scope: "retention:fixture".into(),
            anchor_universe: ContentDigest::sha256(b"replay-admission-fixture"),
            generation: 1,
        })?;
        Ok(ReplayCx::from_context_authority_read_only(
            &authority,
            self.root(),
        )?)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn binding() -> Test<SourceBinding> {
    Ok(SourceBinding {
        sensor_id: SensorId::parse("sensor:admission")?,
        device_generation: ContentDigest::sha256(b"admission-device-v1"),
        profile_generation: ContentDigest::sha256(b"admission-profile-v1"),
        profile_token: "main".into(),
        receive_interval: CaptureInterval::new(TimestampNs(100), TimestampNs(110))?,
    })
}

const SOURCE: &[u8] = br#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:e="http://www.onvif.org/ver10/events/wsdl"><s:Body><e:PullMessagesResponse><e:CurrentTime>2026-10-27T00:00:00Z</e:CurrentTime><e:TerminationTime>2026-10-27T00:02:00Z</e:TerminationTime></e:PullMessagesResponse></s:Body></s:Envelope>"#;

#[test]
fn default_context_keeps_legacy_send_sync_and_active_behavior() -> Test {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ReplayCx>();
    assert_send_sync::<ReplayIoAuthority>();
    let directory = Directory::new()?;
    let cx = directory.cx()?;
    assert!(!directory.root().exists());
    cx.checkpoint("legacy")?;
    assert!(!cx.is_cancelled());
    assert!(cx.io_authority().is_valid());
    assert_eq!(cx.admission_refusal(), None);
    Ok(())
}

#[test]
fn scoped_callback_borrows_non_sync_owner_and_observes_named_checkpoints() -> Test {
    let directory = Directory::new()?;
    let count = Cell::new(0);
    let last_stage = Cell::new("");
    let cx = directory.cx()?.with_admission(|stage| {
        count.set(count.get() + 1);
        last_stage.set(stage);
        Ok(())
    });
    cx.checkpoint("native-owner:read")?;
    assert_eq!(count.get(), 1);
    assert_eq!(last_stage.get(), "native-owner:read");
    assert!(cx.io_authority().is_valid());
    assert_eq!(count.get(), 2);
    assert!(!cx.is_cancelled());
    assert_eq!(count.get(), 3);
    assert!(!directory.root().exists());
    Ok(())
}

#[test]
fn every_owner_refusal_is_sticky_and_later_success_cannot_reopen_admission() -> Test {
    for refusal in [
        ReplayAdmissionError::Cancelled,
        ReplayAdmissionError::Deadline,
        ReplayAdmissionError::Authority,
        ReplayAdmissionError::Budget,
    ] {
        let directory = Directory::new()?;
        let refuse = Cell::new(true);
        let calls = Cell::new(0);
        let cx = directory.cx()?.with_admission(|_| {
            calls.set(calls.get() + 1);
            if refuse.get() { Err(refusal) } else { Ok(()) }
        });
        assert!(matches!(
            cx.checkpoint("native-owner:refuse"),
            Err(ReplayAdapterError::CancellationRequested)
        ));
        refuse.set(false);
        assert!(cx.is_cancelled());
        assert!(!cx.io_authority().is_valid());
        assert!(cx.checkpoint("native-owner:retry").is_err());
        assert_eq!(cx.admission_refusal(), Some(refusal));
        assert_eq!(cx.io_authority().admission_refusal(), Some(refusal));
        assert_eq!(calls.get(), 1);
        assert!(cx.is_drain_completed());
    }
    Ok(())
}

#[test]
fn direct_io_authority_refusal_reaches_context_without_creating_a_directory() -> Test {
    let directory = Directory::new()?;
    let cx = directory
        .cx()?
        .with_admission(|_| Err(ReplayAdmissionError::Authority));
    assert!(ScopedLedgerDir::from_authority("must_not_exist", cx.io_authority()).is_err());
    assert_eq!(
        cx.admission_refusal(),
        Some(ReplayAdmissionError::Authority)
    );
    assert!(cx.is_cancelled());
    assert!(!directory.root().exists());
    Ok(())
}

#[test]
fn attaching_an_owner_cannot_reactivate_a_revoked_context() -> Test {
    let directory = Directory::new()?;
    let cx = directory.cx()?;
    cx.io_authority().revoke();
    let calls = Cell::new(0);
    let cx = cx.with_admission(|_| {
        calls.set(calls.get() + 1);
        Ok(())
    });
    assert!(cx.checkpoint("native-owner:after-revoke").is_err());
    assert_eq!(calls.get(), 0);
    assert!(cx.is_drain_completed());
    Ok(())
}

#[test]
fn recursive_owner_admission_fails_closed_without_panicking_or_restoring_state() -> Test {
    let directory = Directory::new()?;
    let nested = RefCell::new(None::<&dyn Fn() -> bool>);
    let cx = directory.cx()?.with_admission(|_| {
        let borrowed = nested.borrow();
        assert!(!borrowed.as_ref().ok_or(ReplayAdmissionError::Authority)?());
        Ok(())
    });
    let probe = || cx.io_authority().is_valid();
    nested.replace(Some(&probe));
    assert!(cx.checkpoint("native-owner:outer").is_err());
    nested.replace(None);
    assert_eq!(
        cx.admission_refusal(),
        Some(ReplayAdmissionError::Reentrant)
    );
    assert!(!cx.io_authority().is_valid());
    assert!(cx.is_drain_completed());
    Ok(())
}

#[test]
#[allow(
    clippy::panic,
    reason = "Inject an owner callback unwind to verify the admission guard fails closed"
)]
fn unwinding_owner_admission_cannot_leave_a_reusable_context() -> Test {
    let directory = Directory::new()?;
    let cx = directory.cx()?.with_admission(|_| {
        panic!("injected owner callback unwind");
        #[allow(unreachable_code)]
        Ok(())
    });
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = cx.checkpoint("native-owner:panic");
    }));
    assert!(panic.is_err());
    assert_eq!(cx.admission_refusal(), Some(ReplayAdmissionError::Panicked));
    assert!(cx.checkpoint("native-owner:after-panic").is_err());
    assert!(cx.is_drain_completed());
    Ok(())
}

#[test]
fn concurrent_context_handles_share_sticky_owner_refusal() -> Test {
    let directory = Directory::new()?;
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let owner_entered = Arc::clone(&entered);
    let owner_release = Arc::clone(&release);
    let cx = Arc::new(directory.cx()?.with_admission(move |_| {
        owner_entered.wait();
        owner_release.wait();
        Ok(())
    }));
    let worker_cx = Arc::clone(&cx);
    let worker = std::thread::spawn(move || worker_cx.checkpoint("native-owner:inflight").is_err());
    entered.wait();
    let refused = !cx.io_authority().is_valid();
    release.wait();
    assert!(refused);
    assert!(
        worker
            .join()
            .map_err(|_| "owner callback thread panicked")?
    );
    assert_eq!(
        cx.admission_refusal(),
        Some(ReplayAdmissionError::Reentrant)
    );
    assert_eq!(
        cx.io_authority().admission_refusal(),
        cx.admission_refusal()
    );
    assert!(cx.is_cancelled());
    assert!(cx.is_drain_completed());
    Ok(())
}

#[test]
fn publication_bridge_polls_the_same_live_owner_at_cut_points() -> Test {
    let directory = Directory::new()?;
    let cx = directory.cx()?.with_admission(|stage| {
        if stage == STAGE_AFTER_ROOT_TEMP_WRITE {
            Err(ReplayAdmissionError::Deadline)
        } else {
            Ok(())
        }
    });
    let bridge = ReplayCancellationBridge(&cx);
    assert!(bridge.cancel_requested(PublishCutPoint::AfterRootTempWrite));
    assert_eq!(cx.admission_refusal(), Some(ReplayAdmissionError::Deadline));
    assert!(cx.is_drain_completed());
    Ok(())
}

#[test]
fn native_refusal_before_deployment_open_performs_no_initialization() -> Test {
    let directory = Directory::new()?;
    let cx = directory
        .cx()?
        .with_admission(|_| Err(ReplayAdmissionError::Deadline));
    assert!(ReferenceDeployment::open(&directory.root(), "site:admission", &cx).is_err());
    assert!(!directory.root().exists());
    assert_eq!(cx.admission_refusal(), Some(ReplayAdmissionError::Deadline));
    Ok(())
}

#[test]
fn native_refusal_during_metadata_root_publication_leaves_no_authority_claim() -> Test {
    let directory = Directory::new()?;
    let cx = directory.cx()?.with_admission(|stage| {
        if stage == STAGE_AFTER_ROOT_TEMP_WRITE {
            Err(ReplayAdmissionError::Cancelled)
        } else {
            Ok(())
        }
    });
    let mut deployment = ReferenceDeployment::open(&directory.root(), "site:admission", &cx)?;
    assert!(retain(&mut deployment, binding()?, SOURCE, &cx).is_err());
    assert_eq!(
        cx.admission_refusal(),
        Some(ReplayAdmissionError::Cancelled)
    );
    assert!(deployment.ledger().batches().is_empty());
    assert_eq!(deployment.publisher().visible_roots().count(), 0);
    drop(deployment);
    let fresh = directory.cx()?;
    let reopened = ReferenceDeployment::reopen(&directory.root(), "site:admission", &fresh)?;
    assert!(reopened.ledger().batches().is_empty());
    assert_eq!(reopened.publisher().visible_roots().count(), 0);
    Ok(())
}

#[test]
fn native_refusal_after_metadata_commit_preserves_receipt_for_cold_recovery() -> Test {
    let directory = Directory::new()?;
    let cx = directory.cx()?.with_admission(|stage| {
        if stage == "onvif_metadata:committed" {
            Err(ReplayAdmissionError::Deadline)
        } else {
            Ok(())
        }
    });
    let retained = {
        let mut deployment = ReferenceDeployment::open(&directory.root(), "site:admission", &cx)?;
        let retained = retain(&mut deployment, binding()?, SOURCE, &cx)?;
        assert_eq!(deployment.ledger().batches().len(), 1);
        retained
    };
    assert_eq!(cx.admission_refusal(), Some(ReplayAdmissionError::Deadline));
    assert!(cx.is_drain_completed());
    let fresh = directory.cx()?;
    let reopened = ReferenceDeployment::reopen(&directory.root(), "site:admission", &fresh)?;
    let verified = RetainedMetadata::open(
        &reopened,
        retained.identity(),
        Some(retained.publication_root()),
        &fresh,
    )?;
    assert_eq!(verified.authority_anchor(), retained.authority_anchor());
    assert_eq!(verified.source_digest(), retained.source_digest());
    Ok(())
}
