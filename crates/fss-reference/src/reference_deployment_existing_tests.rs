#![forbid(unsafe_code)]
//! Existing deployment evaluation cannot initialize history or reconcile unrelated effects.

use std::cell::Cell;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, EffectIntent, EffectState, IdempotencyKey,
    ObligationId, ObligationState, OperationId, RootAuthoritySpec, TimestampNs,
};

use super::{
    DEPLOYMENT_LAYOUT_FILENAME, DeploymentLimits, DeploymentOpenMode, RELATIVE_PATH_EFFECTS,
    RELATIVE_PATH_LEDGER, RELATIVE_PATH_OBJECTS, ReferenceDeployment,
};
use crate::{ADP_REPLAY_ROW_ID, ReferenceError, ReplayCx};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const SITE: &str = "site:existing-evaluation";

struct Fixture {
    root: PathBuf,
    cx: ReplayCx,
}

impl Fixture {
    fn new(label: &str) -> TestResult<Self> {
        let root = std::env::temp_dir().join(format!(
            "fss-existing-evaluation-{label}-{}",
            std::process::id()
        ));
        match fs::remove_dir_all(&root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: format!("trace:existing-evaluation:{label}"),
            operation_id: OperationId::parse(format!("operation:existing-evaluation:{label}"))?,
            principal: "operator:existing-evaluation".to_owned(),
            capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::default(),
            privacy_scope: "privacy:internal".to_owned(),
            retention_scope: "retention:ephemeral".to_owned(),
            anchor_universe: ContentDigest::sha256(b"existing-evaluation-tests"),
            generation: 1,
        })?;
        // Constructing the inspection context itself must not create the root being tested.
        let cx = ReplayCx::from_context_authority_read_only(&authority, root.clone())?;
        Ok(Self { root, cx })
    }

    fn initialize(&self) -> TestResult<ReferenceDeployment> {
        Ok(ReferenceDeployment::open(&self.root, SITE, &self.cx)?)
    }

    fn evaluate_open(&self) -> Result<ReferenceDeployment, ReferenceError> {
        ReferenceDeployment::open_existing_without_effect_reconciliation(&self.root, SITE, &self.cx)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.root);
    }
}

fn assert_missing(
    result: Result<ReferenceDeployment, ReferenceError>,
    root: &Path,
    relative: &str,
) -> TestResult {
    match result {
        Err(ReferenceError::NotADeployment { path }) if relative == DEPLOYMENT_LAYOUT_FILENAME => {
            assert_eq!(path, root);
        }
        Err(ReferenceError::MissingDeploymentJournal { path })
            if relative != DEPLOYMENT_LAYOUT_FILENAME =>
        {
            assert_eq!(path, root.join(relative));
        }
        other => return Err(format!("expected missing {relative} refusal, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn evaluation_open_never_initializes_an_absent_or_empty_root() -> TestResult {
    let fixture = Fixture::new("absent")?;
    assert!(!fixture.root.exists());
    assert_missing(
        fixture.evaluate_open(),
        &fixture.root,
        DEPLOYMENT_LAYOUT_FILENAME,
    )?;
    assert!(!fixture.root.exists());

    fs::create_dir(&fixture.root)?;
    assert_missing(
        fixture.evaluate_open(),
        &fixture.root,
        DEPLOYMENT_LAYOUT_FILENAME,
    )?;
    assert!(fs::read_dir(&fixture.root)?.next().is_none());
    assert!(!fixture.root.join(RELATIVE_PATH_OBJECTS).exists());
    Ok(())
}

#[test]
fn evaluation_open_refuses_missing_layout_or_even_empty_journals_before_cleanup() -> TestResult {
    for (label, relative) in [
        ("layout", DEPLOYMENT_LAYOUT_FILENAME),
        ("ledger", RELATIVE_PATH_LEDGER),
        ("effects", RELATIVE_PATH_EFFECTS),
    ] {
        let fixture = Fixture::new(label)?;
        drop(fixture.initialize()?);
        fs::remove_file(fixture.root.join(relative))?;
        let temporary = fixture.root.join("LAYOUT.tmp.preserve-evaluation-clue");
        fs::write(&temporary, b"unfinished layout evidence")?;
        assert_missing(fixture.evaluate_open(), &fixture.root, relative)?;
        assert!(!fixture.root.join(relative).exists());
        assert_eq!(fs::read(&temporary)?, b"unfinished layout evidence");
    }
    Ok(())
}

#[test]
fn evaluation_open_rechecks_layout_and_journals_under_the_publisher_lock() -> TestResult {
    for (label, relative) in [
        ("locked-layout", DEPLOYMENT_LAYOUT_FILENAME),
        ("locked-ledger", RELATIVE_PATH_LEDGER),
        ("locked-effects", RELATIVE_PATH_EFFECTS),
    ] {
        let fixture = Fixture::new(label)?;
        drop(fixture.initialize()?);
        let temporary = fixture.root.join("LAYOUT.tmp.preserve-locked-clue");
        fs::write(&temporary, b"unfinished layout evidence")?;
        let removed = Cell::new(false);
        let result = ReferenceDeployment::open_with_mode(
            &fixture.root,
            SITE,
            DeploymentLimits::standard(),
            &fixture.cx,
            &|root| removed.set(fs::remove_file(root.join(relative)).is_ok()),
            DeploymentOpenMode::ExistingWithoutEffectReconciliation,
        );
        assert!(removed.get(), "fault injection did not remove {relative}");
        assert_missing(result, &fixture.root, relative)?;
        assert!(!fixture.root.join(relative).exists());
        assert_eq!(fs::read(&temporary)?, b"unfinished layout evidence");
    }
    Ok(())
}

#[test]
fn evaluation_preserves_pending_effects_and_normal_open_still_reconciles() -> TestResult {
    let fixture = Fixture::new("pending-effects")?;
    let mut deployment = fixture.initialize()?;
    let mut operations = Vec::new();
    for label in ["prepared", "committed"] {
        let intent = EffectIntent::new(
            OperationId::parse(format!("operation:existing-evaluation:{label}"))?,
            IdempotencyKey::parse(format!("idempotency:existing-evaluation:{label}"))?,
            "fixture:notification",
            ContentDigest::sha256(label.as_bytes()),
            ContentDigest::sha256(b"existing-evaluation-authority"),
        )?;
        let obligation = ObligationId::parse(format!("obligation:existing-evaluation:{label}"))?;
        deployment.effects_mut().prepare(
            intent.clone(),
            obligation.clone(),
            "notification observed",
            TimestampNs(1),
        )?;
        if label == "committed" {
            deployment.effects_mut().transition(
                &intent.operation_id,
                EffectState::Committed,
                TimestampNs(2),
                None,
                None,
            )?;
        }
        operations.push((intent.operation_id, obligation));
    }
    let payload = deployment.stage_payload(b"unreferenced retained evaluation evidence")?;
    let anchor = deployment.current_anchor().clone();
    drop(deployment);
    let ledger_path = fixture.root.join(RELATIVE_PATH_LEDGER);
    let effects_path = fixture.root.join(RELATIVE_PATH_EFFECTS);
    let ledger_before = fs::read(&ledger_path)?;
    let effects_before = fs::read(&effects_path)?;
    let temporary = fixture.root.join("LAYOUT.tmp.local-recovery-still-runs");
    fs::write(&temporary, b"stale layout temporary")?;

    for _ in 0..2 {
        let evaluation = fixture.evaluate_open()?;
        assert_eq!(evaluation.current_anchor(), &anchor);
        assert!(evaluation.restart_reclassified().is_empty());
        assert!(
            evaluation
                .recovery_report()
                .unreferenced_objects
                .contains(&payload)
        );
        for ((operation, obligation), state) in operations
            .iter()
            .zip([EffectState::Prepared, EffectState::Committed])
        {
            assert_eq!(
                evaluation.effects().operation(operation).map(|op| op.state),
                Some(state)
            );
            assert_eq!(
                evaluation
                    .effects()
                    .obligation(obligation)
                    .map(|ob| ob.state),
                Some(ObligationState::Pending)
            );
        }
        assert!(
            !temporary.exists(),
            "local publisher/layout recovery remains active"
        );
        assert_eq!(fs::read(&ledger_path)?, ledger_before);
        assert_eq!(fs::read(&effects_path)?, effects_before);
    }

    let ordinary = ReferenceDeployment::open(&fixture.root, SITE, &fixture.cx)?;
    assert_eq!(ordinary.restart_reclassified(), &[operations[1].0.clone()]);
    assert_eq!(
        ordinary
            .effects()
            .operation(&operations[1].0)
            .map(|op| op.state),
        Some(EffectState::Indeterminate)
    );
    assert_eq!(
        ordinary
            .effects()
            .obligation(&operations[1].1)
            .map(|ob| ob.state),
        Some(ObligationState::Indeterminate)
    );
    assert_eq!(
        ordinary
            .effects()
            .operation(&operations[0].0)
            .map(|op| op.state),
        Some(EffectState::Prepared)
    );
    let reconciled = fs::read(&effects_path)?;
    assert!(reconciled.starts_with(&effects_before));
    assert!(reconciled.len() > effects_before.len());
    assert_eq!(fs::read(&ledger_path)?, ledger_before);
    drop(ordinary);
    let reopened = ReferenceDeployment::reopen(&fixture.root, SITE, &fixture.cx)?;
    assert!(reopened.restart_reclassified().is_empty());
    assert_eq!(fs::read(&effects_path)?, reconciled);
    Ok(())
}
