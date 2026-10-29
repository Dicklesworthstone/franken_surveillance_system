#![forbid(unsafe_code)]
//! Lost deployment history is never silently replaced with a fresh journal.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use fss_core::{
    AgentView, BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, EffectIntent,
    EffectState, IdempotencyKey, KnowledgeState, MeaningfulDeltaClass, ObligationId, OperationId,
    PrincipalId, RootAuthoritySpec, TimestampNs,
};
use fss_publication::SlotName;
use fss_reference::agent_follow::{
    AnchorToken, FollowRequest, follow_deployment, snapshot_anchor_token,
};
use fss_reference::agent_orient::{
    CLAIM_EFFECT_JOURNAL, DeploymentHistory, DeploymentReadError, OrientLimits, OrientRequest,
    orient_deployment, read_deployment,
};
use fss_reference::reference_deployment::{RELATIVE_PATH_EFFECTS, RELATIVE_PATH_LEDGER};
use fss_reference::{
    ADP_REPLAY_ROW_ID, DEPLOYMENT_LAYOUT_FILENAME, DeploymentLayout, DeploymentLimits,
    ReferenceDeployment, ReferenceError, ReplayCx, ReplayIoAuthority,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const SITE: &str = "site:missing-journal";
const CHILD_ROOT: &str = "FSS_MISSING_JOURNAL_TEST_ROOT";
const CHILD_JOURNAL: &str = "FSS_MISSING_JOURNAL_TEST_PATH";

struct Fixture {
    root: PathBuf,
    cx: ReplayCx,
}

impl Fixture {
    fn new(tag: &str) -> TestResult<Self> {
        let root =
            std::env::temp_dir().join(format!("fss-missing-journal-{tag}-{}", std::process::id()));
        match fs::remove_dir_all(&root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(Self {
            root,
            cx: context(tag)?,
        })
    }

    fn open(&self) -> Result<ReferenceDeployment, ReferenceError> {
        ReferenceDeployment::open(&self.root, SITE, &self.cx)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.root);
    }
}

fn context(tag: &str) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: format!("trace:missing-journal:{tag}"),
        operation_id: OperationId::parse(format!("operation:missing-journal:{tag}"))?,
        principal: "operator:missing-journal".to_owned(),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".to_owned(),
        retention_scope: "retention:ephemeral".to_owned(),
        anchor_universe: ContentDigest::sha256(b"missing-journal-test"),
        generation: 1,
    })?;
    let scratch = std::env::temp_dir().join(format!(
        "fss-missing-journal-cx-{tag}-{}",
        std::process::id()
    ));
    Ok(ReplayCx::new(ReplayIoAuthority::from_context_authority(
        &authority, scratch,
    )?))
}

#[derive(Debug, Eq, PartialEq)]
enum Entry {
    Directory,
    File(Vec<u8>),
    Symlink(PathBuf),
}

fn tree(root: &Path) -> TestResult<BTreeMap<PathBuf, Entry>> {
    fn visit(base: &Path, path: &Path, entries: &mut BTreeMap<PathBuf, Entry>) -> TestResult {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            let relative = path.strip_prefix(base)?.to_path_buf();
            let kind = entry.file_type()?;
            if kind.is_dir() {
                entries.insert(relative, Entry::Directory);
                visit(base, &path, entries)?;
            } else if kind.is_symlink() {
                entries.insert(relative, Entry::Symlink(fs::read_link(&path)?));
            } else {
                entries.insert(relative, Entry::File(fs::read(&path)?));
            }
        }
        Ok(())
    }
    let mut entries = BTreeMap::new();
    visit(root, root, &mut entries)?;
    Ok(entries)
}

fn assert_missing(result: Result<ReferenceDeployment, ReferenceError>, path: &Path) -> TestResult {
    match result {
        Err(ReferenceError::MissingDeploymentJournal { path: missing }) => {
            assert_eq!(missing, path);
            Ok(())
        }
        other => {
            Err(format!("expected missing-journal refusal for {path:?}, got {other:?}").into())
        }
    }
}

fn intent(name: &str) -> TestResult<EffectIntent> {
    Ok(EffectIntent::new(
        OperationId::parse(format!("operation:missing-journal:{name}"))?,
        IdempotencyKey::parse(format!("idempotency:missing-journal:{name}"))?,
        "fixture:notification",
        ContentDigest::sha256(name.as_bytes()),
        ContentDigest::sha256(b"retained-authority"),
    )?)
}

#[test]
fn missing_journals_refuse_in_a_fresh_process_and_original_history_recovers() -> TestResult {
    for (tag, removed) in [
        ("effects", vec![RELATIVE_PATH_EFFECTS]),
        ("ledger", vec![RELATIVE_PATH_LEDGER]),
        ("both", vec![RELATIVE_PATH_LEDGER, RELATIVE_PATH_EFFECTS]),
    ] {
        let fixture = Fixture::new(tag)?;
        let mut deployment = fixture.open()?;
        let payload = b"evidence retained before journal loss";
        let payload_digest = ContentDigest::sha256(payload);
        let slot = SlotName::parse("retained-evidence")?;
        let staged = deployment.stage_and_publish(&slot, &[payload], &fixture.cx)?;
        deployment.publish_and_commit(
            &slot,
            &staged.manifest,
            CaptureInterval::new(TimestampNs(1), TimestampNs(2))?,
            &fixture.cx,
        )?;
        let anchor = deployment.current_anchor().clone();
        let prepared = intent("prepared")?;
        let committed = intent("committed")?;
        let obligation = ObligationId::parse("obligation:missing-journal:prepared")?;
        deployment.effects_mut().prepare(
            prepared.clone(),
            obligation.clone(),
            "notification observed",
            TimestampNs(3),
        )?;
        deployment.effects_mut().prepare(
            committed.clone(),
            ObligationId::parse("obligation:missing-journal:committed")?,
            "notification observed",
            TimestampNs(4),
        )?;
        deployment.effects_mut().transition(
            &committed.operation_id,
            EffectState::Committed,
            TimestampNs(5),
            None,
            None,
        )?;
        drop(deployment);

        let original_ledger = fs::read(fixture.root.join(RELATIVE_PATH_LEDGER))?;
        let original_effects = fs::read(fixture.root.join(RELATIVE_PATH_EFFECTS))?;
        for relative in &removed {
            fs::remove_file(fixture.root.join(relative))?;
        }
        // Ordinary opening would also clean this file. Refusal must precede even that cleanup.
        fs::write(
            fixture.root.join("LAYOUT.tmp.preserved"),
            b"retained repair clue",
        )?;
        let before = tree(&fixture.root)?;
        let expected_missing = fixture.root.join(removed[0]);
        assert_missing(fixture.open(), &expected_missing)?;
        assert_eq!(tree(&fixture.root)?, before);

        let child = Command::new(std::env::current_exe()?)
            .args([
                "--ignored",
                "--exact",
                "missing_journal_fresh_process_probe",
            ])
            .env(CHILD_ROOT, &fixture.root)
            .env(CHILD_JOURNAL, &expected_missing)
            .output()?;
        assert!(
            child.status.success(),
            "fresh-process refusal failed: {}{}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        );
        assert_eq!(tree(&fixture.root)?, before);

        // Restoring the exact retained journals, rather than fabricating new ones, preserves
        // custody, the authority anchor, idempotency, and unresolved committed effects.
        for relative in &removed {
            let original = if *relative == RELATIVE_PATH_LEDGER {
                &original_ledger
            } else {
                &original_effects
            };
            fs::write(fixture.root.join(relative), original)?;
        }
        let mut reopened = ReferenceDeployment::reopen(&fixture.root, SITE, &fixture.cx)?;
        assert_eq!(reopened.current_anchor(), &anchor);
        assert_eq!(reopened.publisher().spool().read(payload_digest)?, payload);
        assert_eq!(
            reopened
                .effects()
                .operation(&committed.operation_id)
                .map(|receipt| receipt.state),
            Some(EffectState::Indeterminate)
        );
        assert_eq!(
            reopened
                .effects()
                .operation(&prepared.operation_id)
                .map(|receipt| receipt.state),
            Some(EffectState::Prepared)
        );
        assert_eq!(reopened.effects().obligations().count(), 2);
        let effects_after_restart = fs::read(fixture.root.join(RELATIVE_PATH_EFFECTS))?;
        assert!(effects_after_restart.starts_with(&original_effects));
        assert_eq!(
            fs::read(fixture.root.join(RELATIVE_PATH_LEDGER))?,
            original_ledger
        );
        reopened.effects_mut().prepare(
            prepared,
            obligation,
            "notification observed",
            TimestampNs(6),
        )?;
        assert_eq!(
            fs::read(fixture.root.join(RELATIVE_PATH_EFFECTS))?,
            effects_after_restart
        );
        drop(reopened);
        drop(fixture.open()?);
        assert_eq!(
            fs::read(fixture.root.join(RELATIVE_PATH_EFFECTS))?,
            effects_after_restart
        );
    }
    Ok(())
}

#[test]
#[ignore = "subprocess entry point for the missing-journal recovery contract"]
fn missing_journal_fresh_process_probe() -> TestResult {
    let root = PathBuf::from(std::env::var_os(CHILD_ROOT).ok_or("child root missing")?);
    let path = PathBuf::from(std::env::var_os(CHILD_JOURNAL).ok_or("child journal missing")?);
    assert_missing(
        ReferenceDeployment::reopen(&root, SITE, &context("child")?),
        &path,
    )
}

#[test]
fn new_empty_and_interrupted_initialization_roots_still_open() -> TestResult {
    for (tag, has_layout, existing_journal) in [
        ("new", false, None),
        ("empty", false, None),
        ("layout-only", true, None),
        ("empty-ledger", true, Some(RELATIVE_PATH_LEDGER)),
        ("empty-effects", true, Some(RELATIVE_PATH_EFFECTS)),
    ] {
        let fixture = Fixture::new(tag)?;
        if tag != "new" {
            fs::create_dir_all(&fixture.root)?;
        }
        if has_layout {
            let layout =
                DeploymentLayout::new(SITE, DeploymentLimits::standard().canonical_digest()?);
            fs::write(
                fixture.root.join(DEPLOYMENT_LAYOUT_FILENAME),
                layout.to_canonical_text(),
            )?;
        }
        if let Some(relative) = existing_journal {
            let path = fixture.root.join(relative);
            fs::create_dir_all(path.parent().ok_or("journal parent missing")?)?;
            fs::write(path, [])?;
        }
        let deployment = fixture.open()?;
        assert_eq!(deployment.current_anchor().commit_sequence, 0);
        assert_eq!(deployment.effects().obligations().count(), 0);
        drop(deployment);
        assert!(fixture.root.join(RELATIVE_PATH_LEDGER).is_file());
        assert!(fixture.root.join(RELATIVE_PATH_EFFECTS).is_file());
        drop(fixture.open()?);
    }
    Ok(())
}

#[test]
fn staged_custody_and_unknown_journal_siblings_are_not_empty_skeletons() -> TestResult {
    for (tag, retained) in [
        ("staged", "objects"),
        ("ledger-sibling", "ledger/recovery-evidence"),
        ("effect-sibling", "effects/recovery-evidence"),
        ("publisher-lock", "objects/LOCK"),
        ("spool-lock", "objects/spool/LOCK"),
    ] {
        let fixture = Fixture::new(tag)?;
        let mut deployment = fixture.open()?;
        if retained == "objects" {
            deployment.stage_payload(b"unpublished but retained source evidence")?;
        } else {
            fs::write(fixture.root.join(retained), b"unclassified retained bytes")?;
        }
        drop(deployment);
        // Both journals are still empty; only retained custody or a sibling distinguishes this
        // root from an interrupted initializer. Neither may be ignored by classification.
        fs::remove_file(fixture.root.join(RELATIVE_PATH_LEDGER))?;
        fs::remove_file(fixture.root.join(RELATIVE_PATH_EFFECTS))?;
        let before = tree(&fixture.root)?;
        assert_missing(fixture.open(), &fixture.root.join(RELATIVE_PATH_LEDGER))?;
        assert_eq!(tree(&fixture.root)?, before);
    }
    Ok(())
}

#[test]
fn absent_effect_history_is_unknown_and_cannot_certify_silence() -> TestResult {
    let fixture = Fixture::new("orient-effects")?;
    let mut deployment = fixture.open()?;
    deployment.effects_mut().prepare(
        intent("unavailable")?,
        ObligationId::parse("obligation:missing-journal:unavailable")?,
        "notification observed",
        TimestampNs(1),
    )?;
    drop(deployment);
    fs::remove_file(fixture.root.join(RELATIVE_PATH_EFFECTS))?;
    let before = tree(&fixture.root)?;
    let limits = OrientLimits::default();
    let history = DeploymentHistory::read(&fixture.root, &limits)?;
    let snapshot = history.snapshot_at(history.head())?;
    assert!(!snapshot.effect_journal_present);
    let request = OrientRequest {
        view: AgentView::Brief,
        principal: PrincipalId::parse("principal:missing-journal")?,
        budget_tokens: None,
    };
    let orientation = orient_deployment(&snapshot, &request, &limits)?;
    let cell = orientation
        .capsule()
        .frame
        .knowledge_cells
        .iter()
        .find(|cell| cell.claim_id() == CLAIM_EFFECT_JOURNAL)
        .ok_or("effect journal claim missing")?;
    assert_eq!(cell.knowledge_state(), KnowledgeState::Unknown);
    assert!(cell.statement().contains("does not establish"));
    assert!(
        orientation
            .degradation
            .iter()
            .any(|entry| entry.contains("not evidence of no prior effects"))
    );
    let token =
        AnchorToken::parse(&snapshot_anchor_token(&snapshot)).ok_or("anchor token invalid")?;
    let follow = follow_deployment(
        &history,
        &token,
        &FollowRequest {
            view: request.view,
            principal: request.principal,
            max_entries: 64,
            continuation: None,
        },
    )?;
    assert!(follow.delta.silence_certificate.is_none());
    assert!(
        follow
            .delta
            .classes
            .contains(&MeaningfulDeltaClass::CoverageLoss)
    );
    assert!(
        follow
            .delta
            .coverage_changes
            .iter()
            .any(|change| change.contains(CLAIM_EFFECT_JOURNAL))
    );
    assert_eq!(tree(&fixture.root)?, before);
    Ok(())
}

#[test]
fn absent_authority_history_is_unreadable_instead_of_an_empty_genesis() -> TestResult {
    let fixture = Fixture::new("orient-ledger")?;
    let mut deployment = fixture.open()?;
    deployment.stage_payload(b"retained evidence requires its original authority history")?;
    drop(deployment);
    fs::remove_file(fixture.root.join(RELATIVE_PATH_LEDGER))?;
    let before = tree(&fixture.root)?;
    match read_deployment(&fixture.root, &OrientLimits::default()) {
        Err(DeploymentReadError::Unreadable { reason }) => {
            assert!(reason.contains("authority ledger is missing"));
        }
        other => {
            return Err(format!("expected unavailable authority history, got {other:?}").into());
        }
    }
    assert_eq!(tree(&fixture.root)?, before);
    Ok(())
}
