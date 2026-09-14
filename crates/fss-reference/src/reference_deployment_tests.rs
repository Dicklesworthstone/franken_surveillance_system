#![forbid(unsafe_code)]
//! Crate-internal tests for cancellation inside [`ReferenceDeployment::publish_and_commit`].
//!
//! The replay context is armed to request cancellation when it reaches exactly one registered
//! publication cut point. The entry pre-check therefore passes, and the cancellation fires inside
//! the publish surface, through `LedgeredRootPublisher::publish_and_commit_cancellable` and the
//! [`ReplayCancellationBridge`](crate::reference_deployment::ReplayCancellationBridge).

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec,
    TimestampNs,
};
use fss_object::ObjectManifest;
use fss_publication::{
    LOCAL_ROOTS_DIR, LocalPublicationState, PublishCutPoint, ROOT_RECORD_SUFFIX, SlotName,
};

use crate::reference_deployment::{
    DEPLOYMENT_CANCEL_STAGES, RELATIVE_PATH_LEDGER, RELATIVE_PATH_OBJECTS, ReferenceDeployment,
    STAGE_AFTER_ROOT_RENAME, STAGE_STAGE_MANIFEST, publish_cut_point_stage,
};
use crate::reference_deployment::{DEPLOYMENT_LAYOUT_FILENAME, DeploymentLimits, RecoveryAction};
use crate::{ADP_REPLAY_ROW_ID, ReferenceError, ReplayCx, ReplayIoAuthority};
use fss_core::{BatchId, EvidenceDelta, ObjectId, Plane};
use fss_ledger::AppendPhase;

type TestResult = Result<(), Box<dyn Error>>;

const SLOT: &str = "slot-cut";

fn test_cx(label: &str) -> Result<ReplayCx, Box<dyn Error>> {
    let spec = RootAuthoritySpec {
        trace_id: format!("trace:unit-test-{label}"),
        operation_id: OperationId::parse(format!("operation:unit-test-{label}"))?,
        principal: format!("operator:unit-test-{label}"),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_string()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".to_string(),
        retention_scope: "retention:ephemeral".to_string(),
        anchor_universe: ContentDigest::sha256(b"test-anchor-universe"),
        generation: 1,
    };
    let root_auth = ContextAuthority::new_root(spec)?;
    let scratch_root = std::env::temp_dir().join(format!(
        "test-replay-cx-refdep-unit-{label}-{}",
        std::process::id()
    ));
    let io = ReplayIoAuthority::from_context_authority(&root_auth, scratch_root)?;
    Ok(ReplayCx::new(io))
}

fn fresh_root(tag: &str) -> Result<PathBuf, Box<dyn Error>> {
    let root = std::env::temp_dir().join(format!("fss-refdep-unit-{tag}-{}", std::process::id()));
    match fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(root)
}

fn validity() -> Result<CaptureInterval, Box<dyn Error>> {
    Ok(CaptureInterval::new(TimestampNs(1), TimestampNs(2))?)
}

fn roots_dir_names(root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(root.join(RELATIVE_PATH_OBJECTS).join(LOCAL_ROOTS_DIR))? {
        names.push(entry?.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    Ok(names)
}

/// A cancellation that fires inside `publish_and_commit` at each pre-commit cut point returns
/// `CancellationRequested` naming that registered stage, drains the context, leaves no root record
/// or temporary behind, and leaves the ledger journal byte-identical. The deployment stays usable.
#[test]
fn cancel_inside_publish_and_commit_at_each_pre_commit_cut_point() -> TestResult {
    let points = [
        PublishCutPoint::AfterChildrenVerified,
        PublishCutPoint::AfterManifestBody,
        PublishCutPoint::AfterRootTempWrite,
    ];
    for (index, point) in points.into_iter().enumerate() {
        let stage = publish_cut_point_stage(point);
        assert!(DEPLOYMENT_CANCEL_STAGES.contains(&stage), "{stage}");
        let root = fresh_root(stage)?;
        let open_cx = test_cx(&format!("open-{stage}"))?;
        let mut dep = ReferenceDeployment::open(&root, "site:cut:cancel", &open_cx)?;
        let slot = SlotName::parse(SLOT)?;
        let child = dep.stage_payload(b"cut-point-child")?;
        let manifest = ObjectManifest::new(SLOT, [child], None)?;
        let ledger_path = root.join(RELATIVE_PATH_LEDGER);
        let journal_before = fs::read(&ledger_path)?;
        let anchor_before = dep.current_anchor().clone();

        let cx = test_cx(&format!("cancel-{stage}"))?;
        cx.set_cancel_at_checkpoint(stage);
        assert!(!cx.is_cancelled(), "{stage}: the entry pre-check must pass");
        match dep.publish_and_commit(&slot, &manifest, validity()?, &cx) {
            Err(ReferenceError::CancellationRequested { stage: reported }) => {
                assert_eq!(reported, stage);
            }
            other => {
                return Err(
                    format!("{stage}: expected CancellationRequested, got {other:?}").into(),
                );
            }
        }
        assert!(cx.is_drain_completed(), "{stage}: cancellation must drain");
        assert_eq!(
            cx.checkpoints_reached(),
            index + 1,
            "{stage}: the context must reach every cut point up to the cancelled one"
        );
        assert!(dep.publisher().root(&slot).is_none(), "{stage}");
        assert_eq!(
            roots_dir_names(&root)?,
            Vec::<String>::new(),
            "{stage}: no root record and no temporary may remain"
        );
        assert_eq!(fs::read(&ledger_path)?, journal_before, "{stage}");
        assert!(dep.ledger().batches().is_empty(), "{stage}");
        assert_eq!(dep.current_anchor(), &anchor_before, "{stage}");

        let receipt = dep.publish_and_commit(&slot, &manifest, validity()?, &open_cx)?;
        assert_eq!(receipt.root, manifest.root(), "{stage}");
        assert_eq!(
            dep.publisher().root(&slot).map(|visible| visible.state),
            Some(LocalPublicationState::Durable),
            "{stage}"
        );
        assert_eq!(dep.ledger().batches().len(), 1, "{stage}");
        drop(dep);
        fs::remove_dir_all(&root)?;
    }
    Ok(())
}

/// `after_root_rename` is registered, but it lies past the commit point: the publisher never
/// polls cancellation there, so a context armed for it is never cancelled and the root becomes
/// durable and ledgered.
#[test]
fn cancel_armed_after_root_rename_is_not_honored_past_the_commit_point() -> TestResult {
    let root = fresh_root(STAGE_AFTER_ROOT_RENAME)?;
    let open_cx = test_cx("open-after-root-rename")?;
    let mut dep = ReferenceDeployment::open(&root, "site:cut:cancel", &open_cx)?;
    let slot = SlotName::parse(SLOT)?;
    let child = dep.stage_payload(b"cut-point-child")?;
    let manifest = ObjectManifest::new(SLOT, [child], None)?;

    let cx = test_cx("cancel-after-root-rename")?;
    cx.set_cancel_at_checkpoint(STAGE_AFTER_ROOT_RENAME);
    let receipt = dep.publish_and_commit(&slot, &manifest, validity()?, &cx)?;
    assert_eq!(receipt.root, manifest.root());
    assert!(!cx.is_cancelled());
    assert_eq!(cx.checkpoints_reached(), 3);
    assert_eq!(
        dep.publisher().root(&slot).map(|visible| visible.state),
        Some(LocalPublicationState::Durable)
    );
    assert_eq!(dep.ledger().batches().len(), 1);
    assert_eq!(
        roots_dir_names(&root)?,
        vec![format!("{SLOT}{ROOT_RECORD_SUFFIX}")]
    );
    drop(dep);
    fs::remove_dir_all(&root)?;
    Ok(())
}

/// A cancellation armed for `stage_manifest` passes the entry and per-object checks, fires after
/// the children are staged and before the manifest is built, and stages no manifest for the slot.
#[test]
fn cancel_at_stage_manifest_fires_after_children_are_staged() -> TestResult {
    let root = fresh_root(STAGE_STAGE_MANIFEST)?;
    let open_cx = test_cx("open-stage-manifest")?;
    let mut dep = ReferenceDeployment::open(&root, "site:cut:cancel", &open_cx)?;
    let slot = SlotName::parse(SLOT)?;

    let cx = test_cx("cancel-stage-manifest")?;
    cx.set_cancel_at_checkpoint(STAGE_STAGE_MANIFEST);
    match dep.stage_and_publish(&slot, &[b"stage-manifest-child"], &cx) {
        Err(ReferenceError::CancellationRequested { stage }) => {
            assert_eq!(stage, STAGE_STAGE_MANIFEST);
        }
        other => return Err(format!("expected stage_manifest cancellation, got {other:?}").into()),
    }
    assert!(cx.is_drain_completed());
    assert_eq!(cx.checkpoints_reached(), 1);
    assert!(dep.publisher().root(&slot).is_none());
    assert!(roots_dir_names(&root)?.is_empty());
    assert!(dep.ledger().batches().is_empty());

    // The staged child is custody only; reopening surfaces it as unreferenced.
    drop(dep);
    let dep = ReferenceDeployment::open(&root, "site:cut:cancel", &open_cx)?;
    assert_eq!(
        dep.recovery_report().unreferenced_objects,
        vec![ContentDigest::sha256(b"stage-manifest-child")]
    );
    drop(dep);
    fs::remove_dir_all(&root)?;
    Ok(())
}

/// A journal fault injected after each append phase, then reopen (with the explicit truncation
/// when the tail is torn): an identical retry commits exactly once. In-crate because the fault hook
/// reaches the ledger through the crate-internal `ledger_mut`.
#[test]
fn p13_crash_injection_each_injectable_phase() -> TestResult {
    let cx = test_cx("p13")?;
    for phase in [
        AppendPhase::BodyWrite,
        AppendPhase::BodySync,
        AppendPhase::CommitWrite,
        AppendPhase::CommitSync,
    ] {
        let root = fresh_root(&format!("p13-{phase:?}"))?;
        let batch_id = BatchId::parse("batch:authority:crash")?;
        let (delta, payload) = {
            let mut dep = ReferenceDeployment::open(&root, "site:p13", &cx)?;
            let payload = dep.stage_payload(b"crash-payload")?;
            let delta = EvidenceDelta {
                delta_id: "delta:crash:1".to_owned(),
                family: "sensor_capsule".to_owned(),
                object_id: ObjectId::parse("object:crash:1")?,
                prior_generation: None,
                new_generation: 1,
                validity: CaptureInterval::new(TimestampNs(100), TimestampNs(200))?,
                plane: Plane::Authority,
                payload_digest: payload,
                witness_digest: None,
                operation_id: None,
            };
            dep.ledger_mut().fail_journal_after_phase(phase);
            let _faulted =
                dep.append_batch(batch_id.clone(), vec![delta.clone()], vec![payload], &cx);
            (delta, payload)
        };
        let mut dep = match ReferenceDeployment::open(&root, "site:p13", &cx) {
            Ok(dep) => dep,
            Err(_) => {
                let _recovery = ReferenceDeployment::open_for_recovery(
                    &root,
                    RecoveryAction::TruncateIncompleteLedgerTail,
                    &cx,
                );
                ReferenceDeployment::open(&root, "site:p13", &cx)?
            }
        };
        let anchor = dep.append_batch(batch_id, vec![delta], vec![payload], &cx)?;
        assert_eq!(anchor.commit_sequence, 1, "{phase:?}");
        assert_eq!(dep.ledger().batches().len(), 1, "{phase:?}");
        let _reconciliation = dep.reconcile()?;
        drop(dep);
        fs::remove_dir_all(&root)?;
    }
    Ok(())
}

/// A foreign file that appears after the advisory pre-check and before the classification under
/// the deployment lock is refused there: `NotADeployment`, the foreign file intact, no LAYOUT
/// written (kills r9e U1).
#[test]
fn foreign_file_appearing_after_the_lock_is_refused_under_the_lock() -> TestResult {
    let root = fresh_root("u1-after-lock")?;
    let cx = test_cx("u1-after-lock")?;
    let result = ReferenceDeployment::open_with_after_lock(
        &root,
        "site:u1",
        DeploymentLimits::standard(),
        &cx,
        &|dir: &Path| {
            let _written = fs::write(dir.join("foreign.txt"), b"foreign");
        },
    );
    match result {
        Err(ReferenceError::NotADeployment { path }) => assert_eq!(path, root),
        other => return Err(format!("expected NotADeployment, got {other:?}").into()),
    }
    assert_eq!(fs::read(root.join("foreign.txt"))?, b"foreign");
    assert!(!root.join(DEPLOYMENT_LAYOUT_FILENAME).exists());
    fs::remove_dir_all(&root)?;
    Ok(())
}
