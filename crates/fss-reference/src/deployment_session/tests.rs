#![forbid(unsafe_code)]
//! Unit tests for durable sessions and root-last handoffs over real on-disk deployments.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::{
    AgentView, BatchId, BudgetVector, CaptureInterval, ContentDigest, ContextAuthority,
    EvidenceDelta, HandoffId, ObjectId, OperationId, Plane, PrincipalId, RootAuthoritySpec,
    TimestampNs,
};
use fss_publication::PublishCutPoint;

use super::{
    ANCHOR_ASSUMPTION_ID, DeploymentSessionError, HandoffRecord, HandoffRequest,
    OpenSessionRequest, PUBLICATIONS_RELPATH, ResumeRequest, SESSION_JOURNAL_FILE,
    SESSIONS_RELPATH, capsule_anchor_token, open_session, prepare_handoff, resume_session,
};
use crate::agent_follow::{AnchorRefusal, AnchorToken, resolve_anchor, snapshot_anchor_token};
use crate::agent_orient::{DeploymentHistory, OrientLimits};
use crate::reference_deployment::{RELATIVE_PATH_EFFECTS, RELATIVE_PATH_LEDGER};
use crate::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SITE: &str = "site:session-unit";

struct Fixture {
    root: PathBuf,
    cx: ReplayCx,
    batches: u64,
}

impl Fixture {
    fn new(tag: &str, site: &str) -> TestResult<Self> {
        let root = std::env::temp_dir().join(format!(
            "fss-deployment-session-unit-{tag}-{}",
            std::process::id()
        ));
        match fs::remove_dir_all(&root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let spec = RootAuthoritySpec {
            trace_id: format!("trace:session-unit-{tag}"),
            operation_id: OperationId::parse(format!("operation:session-unit-{tag}"))?,
            principal: format!("operator:session-unit-{tag}"),
            capabilities: vec![ADP_REPLAY_ROW_ID.to_string()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::default(),
            privacy_scope: "privacy:internal".to_string(),
            retention_scope: "retention:ephemeral".to_string(),
            anchor_universe: ContentDigest::sha256(b"session-unit"),
            generation: 1,
        };
        let authority = ContextAuthority::new_root(spec)?;
        let scratch = std::env::temp_dir().join(format!(
            "fss-deployment-session-unit-cx-{tag}-{}",
            std::process::id()
        ));
        let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
            &authority, scratch,
        )?);
        drop(ReferenceDeployment::open(&root, site, &cx)?);
        Ok(Self {
            root,
            cx,
            batches: 0,
        })
    }

    /// Commits one `sensor_capsule` batch through the real deployment append path.
    fn commit(&mut self, site: &str) -> TestResult {
        self.batches += 1;
        let index = self.batches;
        let mut deployment = ReferenceDeployment::open(&self.root, site, &self.cx)?;
        let payload = deployment.stage_payload(format!("capsule-{index}").as_bytes())?;
        let start = i128::from(index) * 1_000;
        deployment.append_batch(
            BatchId::parse(format!("batch:session-unit:{index}"))?,
            vec![EvidenceDelta {
                delta_id: format!("delta:session-unit:{index}"),
                family: "sensor_capsule".to_owned(),
                object_id: ObjectId::parse(format!("object:session-unit:{index}"))?,
                prior_generation: None,
                new_generation: 1,
                validity: CaptureInterval::new(TimestampNs(start), TimestampNs(start + 500))?,
                plane: Plane::Authority,
                payload_digest: payload,
                witness_digest: None,
                operation_id: None,
            }],
            vec![payload],
            &self.cx,
        )?;
        Ok(())
    }

    /// Digests of the authority ledger and the effect journal (absent reads as empty).
    fn authority_digests(&self) -> TestResult<(ContentDigest, ContentDigest)> {
        let read = |relative: &str| -> TestResult<ContentDigest> {
            match fs::read(self.root.join(relative)) {
                Ok(bytes) => Ok(ContentDigest::sha256(&bytes)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    Ok(ContentDigest::sha256(b""))
                }
                Err(error) => Err(error.into()),
            }
        };
        Ok((read(RELATIVE_PATH_LEDGER)?, read(RELATIVE_PATH_EFFECTS)?))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn principal() -> TestResult<PrincipalId> {
    Ok(PrincipalId::parse("principal:session-unit")?)
}

fn open_request() -> TestResult<OpenSessionRequest> {
    Ok(OpenSessionRequest {
        mission: "Keep the east door under watch overnight.".to_owned(),
        objective: "Know whether anyone entered through the east door.".to_owned(),
        principal: principal()?,
        view: AgentView::Brief,
        token_budget: 1_600,
    })
}

fn handoff_request(session: &fss_core::SessionId, note: &str) -> TestResult<HandoffRequest> {
    Ok(HandoffRequest {
        session_id: session.clone(),
        principal: principal()?,
        note: Some(note.to_owned()),
    })
}

fn resume_request(handoff: &HandoffId) -> TestResult<ResumeRequest> {
    Ok(ResumeRequest {
        handoff_id: handoff.clone(),
        principal: principal()?,
    })
}

fn journal_bytes(root: &Path) -> TestResult<Vec<u8>> {
    Ok(fs::read(
        root.join(SESSIONS_RELPATH).join(SESSION_JOURNAL_FILE),
    )?)
}

#[test]
fn open_handoff_resume_on_an_unchanged_deployment_invalidates_nothing() -> TestResult {
    let fixture = Fixture::new("unchanged", SITE)?;
    let authority = fixture.authority_digests()?;
    let opened = open_session(&fixture.root, &open_request()?)?;
    assert_eq!(opened.revision.capsule().revision, 0);
    assert_eq!(
        capsule_anchor_token(opened.revision.capsule()),
        Some(opened.orientation.anchor_token.as_str())
    );
    assert_eq!(
        opened.orientation.capsule().session_id,
        opened.session.session_id,
        "the situation is bound to the durable session"
    );
    let prepared = prepare_handoff(
        &fixture.root,
        &handoff_request(&opened.session.session_id, "night shift ends")?,
    )?;
    prepared.record.capsule.verify()?;
    assert_eq!(
        prepared.record.capsule.source_session_id,
        opened.session.session_id
    );
    assert_eq!(
        prepared.record.capsule.mission_id,
        opened.session.mission_id
    );
    let published = prepared.publish(&[b"rendered".to_vec()])?;
    let resumed = resume_session(
        &fixture.root,
        &resume_request(&published.record.capsule.handoff_id)?,
    )?;
    assert!(!resumed.anchor_moved);
    assert!(resumed.invalidated.is_empty(), "{:?}", resumed.invalidated);
    assert!(!resumed.committed);
    assert_eq!(resumed.revision, opened.revision);
    assert_eq!(
        resumed.session.current_anchor,
        opened.session.current_anchor
    );
    assert!(resumed.delta.changed_cells.is_empty());
    assert!(resumed.delta.invalidated_assumptions.is_empty());
    // Nothing was written to the authority ledger or the effect journal.
    assert_eq!(fixture.authority_digests()?, authority);
    Ok(())
}

#[test]
fn resume_after_a_commit_lists_invalidations_and_rebases_exactly_once() -> TestResult {
    let mut fixture = Fixture::new("advanced", SITE)?;
    let opened = open_session(&fixture.root, &open_request()?)?;
    let published = prepare_handoff(
        &fixture.root,
        &handoff_request(&opened.session.session_id, "handing over")?,
    )?
    .publish(&[])?;
    fixture.commit(SITE)?;
    let authority = fixture.authority_digests()?;
    let request = resume_request(&published.record.capsule.handoff_id)?;
    let resumed = resume_session(&fixture.root, &request)?;
    assert!(resumed.anchor_moved);
    assert!(resumed.committed);
    assert_eq!(resumed.revision.capsule().revision, 1);
    assert_eq!(
        resumed.revision.parent_digest(),
        Some(opened.revision.digest())
    );
    assert_eq!(
        resumed.session.current_anchor,
        resumed.result.capsule().anchor,
        "the session is rebased onto the head"
    );
    assert!(
        resumed
            .invalidated
            .iter()
            .any(|line| line.starts_with(&format!("assumption {ANCHOR_ASSUMPTION_ID} invalidated")))
    );
    assert!(
        resumed
            .invalidated
            .iter()
            .any(|line| line.starts_with("claim "))
    );
    // A rebase keeps every earlier assumption as explicit debt and drops no action silently.
    let capsule = resumed.revision.capsule();
    for assumption in &opened.revision.capsule().assumptions {
        assert!(capsule.epistemic_debt.contains(assumption), "{assumption}");
    }
    assert!(capsule.next_actions.is_empty());
    assert_eq!(
        resumed.revision.invalidated_actions(),
        opened.revision.capsule().next_actions.as_slice()
    );
    // Resuming the same handoff again reports the same invalidations and commits nothing new.
    let journal = journal_bytes(&fixture.root)?;
    let again = resume_session(&fixture.root, &request)?;
    assert!(!again.committed);
    assert_eq!(again.revision, resumed.revision);
    assert_eq!(again.invalidated, resumed.invalidated);
    assert_eq!(journal_bytes(&fixture.root)?, journal);
    assert_eq!(fixture.authority_digests()?, authority);
    Ok(())
}

#[test]
fn identical_open_is_an_exact_retry() -> TestResult {
    let fixture = Fixture::new("idempotent", SITE)?;
    let first = open_session(&fixture.root, &open_request()?)?;
    let journal = journal_bytes(&fixture.root)?;
    let second = open_session(&fixture.root, &open_request()?)?;
    assert_eq!(second, first);
    assert_eq!(journal_bytes(&fixture.root)?, journal);
    // Another objective is another session of another mission.
    let mut other = open_request()?;
    other.objective = "Count deliveries at the east door.".to_owned();
    let third = open_session(&fixture.root, &other)?;
    assert_ne!(third.session.session_id, first.session.session_id);
    assert_ne!(third.session.mission_id, first.session.mission_id);
    Ok(())
}

#[test]
fn a_handoff_interrupted_at_every_cut_point_is_absent_or_complete() -> TestResult {
    for (index, point) in [
        PublishCutPoint::AfterChildrenVerified,
        PublishCutPoint::AfterManifestBody,
        PublishCutPoint::AfterRootTempWrite,
        PublishCutPoint::AfterRootRename,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = Fixture::new(&format!("crash-{index}"), SITE)?;
        let opened = open_session(&fixture.root, &open_request()?)?;
        let request = handoff_request(&opened.session.session_id, "interrupted")?;
        let prepared = prepare_handoff(&fixture.root, &request)?;
        let handoff_id = prepared.record.capsule.handoff_id.clone();
        let crashed = prepared.publish_at(&[b"child".to_vec()], Some(point));
        assert!(
            matches!(crashed, Err(DeploymentSessionError::StoreInvalid(_))),
            "{point}: {crashed:?}"
        );
        let resumed = resume_session(&fixture.root, &resume_request(&handoff_id)?);
        if point == PublishCutPoint::AfterRootRename {
            // Past the commit point the root is complete and verifies end to end.
            let resumed = resumed?;
            assert_eq!(resumed.handoff.capsule.handoff_id, handoff_id);
        } else {
            assert!(
                matches!(resumed, Err(DeploymentSessionError::HandoffUnknown)),
                "{point}: {resumed:?}"
            );
            // A retry either completes the publication or is refused typed (an orphaned temporary
            // record is never adopted implicitly); it never exposes a partial root.
            match prepare_handoff(&fixture.root, &request)?.publish(&[b"child".to_vec()]) {
                Ok(published) => {
                    let resumed = resume_session(&fixture.root, &resume_request(&handoff_id)?)?;
                    assert_eq!(resumed.handoff, published.record);
                }
                Err(DeploymentSessionError::StoreInvalid(_)) => {
                    assert_eq!(point, PublishCutPoint::AfterRootTempWrite);
                    assert!(matches!(
                        resume_session(&fixture.root, &resume_request(&handoff_id)?),
                        Err(DeploymentSessionError::HandoffUnknown)
                    ));
                }
                Err(other) => return Err(format!("{point}: {other}").into()),
            }
        }
    }
    Ok(())
}

#[test]
fn tampered_unknown_foreign_and_unauthorized_handoffs_are_refused() -> TestResult {
    let fixture = Fixture::new("refusals", SITE)?;
    let opened = open_session(&fixture.root, &open_request()?)?;
    let published = prepare_handoff(
        &fixture.root,
        &handoff_request(&opened.session.session_id, "refusals")?,
    )?
    .publish(&[])?;
    let handoff_id = published.record.capsule.handoff_id.clone();

    // A consistently re-encoded record with an altered field no longer reproduces its root.
    let mut forged = published.record.clone();
    forged.capsule.created_at = TimestampNs(forged.capsule.created_at.0 + 1);
    assert!(HandoffRecord::from_bytes(&forged.to_bytes()?).is_err());
    assert_eq!(
        HandoffRecord::from_bytes(&published.record.to_bytes()?)?,
        published.record
    );

    // Unknown identity.
    assert!(matches!(
        resume_session(
            &fixture.root,
            &resume_request(&HandoffId::parse("handoff:unknown")?)?
        ),
        Err(DeploymentSessionError::HandoffUnknown)
    ));
    // Outside the recipient scope.
    let mut stranger = resume_request(&handoff_id)?;
    stranger.principal = PrincipalId::parse("principal:stranger")?;
    assert!(matches!(
        resume_session(&fixture.root, &stranger),
        Err(DeploymentSessionError::HandoffInvalid(_))
    ));

    // Foreign: the same publication copied into another deployment.
    let other = Fixture::new("refusals-foreign", "site:session-unit-other")?;
    copy_tree(
        &fixture.root.join(PUBLICATIONS_RELPATH),
        &other.root.join(PUBLICATIONS_RELPATH),
    )?;
    assert!(matches!(
        resume_session(&other.root, &resume_request(&handoff_id)?),
        Err(DeploymentSessionError::HandoffInvalid(_))
    ));

    // Tampered spool bytes: the published root no longer verifies.
    let mut tampered = 0;
    for file in files_under(&fixture.root.join(PUBLICATIONS_RELPATH).join("spool"))? {
        let mut bytes = fs::read(&file)?;
        if bytes
            .windows(handoff_id.as_str().len())
            .any(|window| window == handoff_id.as_str().as_bytes())
        {
            let last = bytes.len() - 1;
            bytes[last] ^= 0x01;
            fs::write(&file, bytes)?;
            tampered += 1;
        }
    }
    assert!(tampered > 0, "the handoff record was found in the spool");
    assert!(matches!(
        resume_session(&fixture.root, &resume_request(&handoff_id)?),
        Err(DeploymentSessionError::HandoffInvalid(_))
    ));
    Ok(())
}

#[test]
fn a_rolled_back_session_journal_is_refused() -> TestResult {
    let mut fixture = Fixture::new("rollback", SITE)?;
    let opened = open_session(&fixture.root, &open_request()?)?;
    let early = journal_bytes(&fixture.root)?;
    let published = prepare_handoff(
        &fixture.root,
        &handoff_request(&opened.session.session_id, "rollback")?,
    )?
    .publish(&[])?;
    fixture.commit(SITE)?;
    resume_session(
        &fixture.root,
        &resume_request(&published.record.capsule.handoff_id)?,
    )?;
    fs::write(
        fixture
            .root
            .join(SESSIONS_RELPATH)
            .join(SESSION_JOURNAL_FILE),
        early,
    )?;
    assert!(matches!(
        open_session(&fixture.root, &open_request()?),
        Err(DeploymentSessionError::StoreInvalid(_))
    ));
    Ok(())
}

/// fss-1s6ac: a deployment root copied byte for byte and advanced on its own is another
/// deployment. Its anchor token after the divergence is refused on the original (the token binds
/// the ledger and effect roots at its position, and the original committed another batch there),
/// and so is a handoff sealed on the copy after the divergence and carried into the original.
/// Before the divergence the copy's token is byte-identical to the original's own: it names history
/// both share, so it is not refused (the residual `SECURITY.md` states).
#[test]
fn a_handoff_and_anchor_from_a_byte_copied_deployment_are_refused_on_the_original() -> TestResult {
    let mut original = Fixture::new("fork-original", SITE)?;
    original.commit(SITE)?;
    let mut fork = Fixture::new("fork-copy", SITE)?;
    fs::remove_dir_all(&fork.root)?;
    copy_tree(&original.root, &fork.root)?;
    fork.batches = original.batches;
    let limits = OrientLimits::default();
    let head_token = |root: &Path| -> TestResult<String> {
        let history = DeploymentHistory::read(root, &limits)?;
        Ok(snapshot_anchor_token(&history.snapshot_at(history.head())?))
    };
    assert_eq!(head_token(&fork.root)?, head_token(&original.root)?);

    // Each advances by a different batch at the same position.
    fork.commit(SITE)?;
    original.batches += 10;
    original.commit(SITE)?;
    let fork_token = head_token(&fork.root)?;
    let original_history = DeploymentHistory::read(&original.root, &limits)?;
    let token = AnchorToken::parse(&fork_token).ok_or("the fork's anchor token does not parse")?;
    assert!(
        matches!(
            resolve_anchor(&original_history, &token),
            Err(AnchorRefusal::Unknown)
        ),
        "{fork_token}"
    );

    let opened = open_session(&fork.root, &open_request()?)?;
    let published = prepare_handoff(
        &fork.root,
        &handoff_request(&opened.session.session_id, "sealed on the copy")?,
    )?
    .publish(&[])?;
    let handoff_id = published.record.capsule.handoff_id.clone();
    copy_tree(
        &fork.root.join(PUBLICATIONS_RELPATH),
        &original.root.join(PUBLICATIONS_RELPATH),
    )?;
    let resumed = resume_session(&original.root, &resume_request(&handoff_id)?);
    assert!(
        matches!(
            &resumed,
            Err(DeploymentSessionError::HandoffInvalid(reason))
                if reason == "the handoff anchor is not in this deployment's committed history"
        ),
        "{:?}",
        resumed.map(|resumed| resumed.revision.capsule().revision)
    );
    // On the copy it was sealed on, the same handoff resumes.
    let _ = resume_session(&fork.root, &resume_request(&handoff_id)?)?;
    Ok(())
}

#[test]
fn equal_committed_bytes_give_equal_sessions_and_handoffs() -> TestResult {
    let run = |tag: &str| -> TestResult<(Vec<u8>, Vec<u8>, Vec<String>)> {
        let mut fixture = Fixture::new(tag, SITE)?;
        let opened = open_session(&fixture.root, &open_request()?)?;
        let published = prepare_handoff(
            &fixture.root,
            &handoff_request(&opened.session.session_id, "determinism")?,
        )?
        .publish(&[])?;
        fixture.commit(SITE)?;
        let resumed = resume_session(
            &fixture.root,
            &resume_request(&published.record.capsule.handoff_id)?,
        )?;
        Ok((
            published.record.to_bytes()?,
            resumed.revision.as_bytes().to_vec(),
            resumed.invalidated,
        ))
    };
    assert_eq!(run("determinism-a")?, run("determinism-b")?);
    Ok(())
}

fn files_under(directory: &Path) -> TestResult<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(&path)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                out.push(entry.path());
            }
        }
    }
    out.sort();
    Ok(out)
}

fn copy_tree(from: &Path, to: &Path) -> TestResult {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}
