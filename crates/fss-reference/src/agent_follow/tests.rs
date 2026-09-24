#![forbid(unsafe_code)]
//! Unit tests for the read-only follow compiler over real on-disk deployments.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use fss_core::{
    AgentView, BatchId, BudgetVector, CaptureInterval, ContentDigest, ContextAuthority,
    ContinuationError, EvidenceDelta, MeaningfulDeltaClass, ObjectId, OperationId, Plane,
    PrincipalId, RootAuthoritySpec, TimestampNs,
};

use super::{
    AnchorRefusal, AnchorToken, DEFAULT_FOLLOW_MAX_ENTRIES, FollowError, FollowItem, FollowRequest,
    follow_deployment, resolve_anchor, snapshot_anchor_token,
};
use crate::agent_orient::{
    CLAIM_LEDGER_HEAD, DeploymentHistory, DeploymentReadError, HistoryPosition, OrientLimits,
    OrientRequest, orient_deployment, read_deployment,
};
use crate::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SITE: &str = "site:follow-unit";

struct Fixture {
    root: PathBuf,
    cx: ReplayCx,
    batches: u64,
}

impl Fixture {
    fn new(tag: &str) -> TestResult<Self> {
        let root = std::env::temp_dir().join(format!(
            "fss-agent-follow-unit-{tag}-{}",
            std::process::id()
        ));
        match fs::remove_dir_all(&root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let spec = RootAuthoritySpec {
            trace_id: format!("trace:follow-unit-{tag}"),
            operation_id: OperationId::parse(format!("operation:follow-unit-{tag}"))?,
            principal: format!("operator:follow-unit-{tag}"),
            capabilities: vec![ADP_REPLAY_ROW_ID.to_string()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::default(),
            privacy_scope: "privacy:internal".to_string(),
            retention_scope: "retention:ephemeral".to_string(),
            anchor_universe: ContentDigest::sha256(b"follow-unit"),
            generation: 1,
        };
        let authority = ContextAuthority::new_root(spec)?;
        let scratch = std::env::temp_dir().join(format!(
            "fss-agent-follow-unit-cx-{tag}-{}",
            std::process::id()
        ));
        let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
            &authority, scratch,
        )?);
        drop(ReferenceDeployment::open(&root, SITE, &cx)?);
        Ok(Self {
            root,
            cx,
            batches: 0,
        })
    }

    /// Commits one `sensor_capsule` batch through the real deployment append path.
    fn commit(&mut self) -> TestResult {
        self.batches += 1;
        let index = self.batches;
        let mut deployment = ReferenceDeployment::open(&self.root, SITE, &self.cx)?;
        let payload = deployment.stage_payload(format!("capsule-{index}").as_bytes())?;
        let start = i128::from(index) * 1_000;
        deployment.append_batch(
            BatchId::parse(format!("batch:follow-unit:{index}"))?,
            vec![EvidenceDelta {
                delta_id: format!("delta:follow-unit:{index}"),
                family: "sensor_capsule".to_owned(),
                object_id: ObjectId::parse(format!("object:follow-unit:{index}"))?,
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

    /// Commits one batch of a derived `decode_receipt` delta whose validity lies inside the
    /// evidence already committed: it retains no source evidence, coverage, event, or effect.
    fn commit_derived(&mut self) -> TestResult {
        self.commit_family("decode_receipt")
    }

    /// Commits one `file_import_manifest` batch (a completed import) inside the committed
    /// evidence interval.
    fn commit_import(&mut self) -> TestResult {
        self.commit_family("file_import_manifest")
    }

    fn commit_family(&mut self, family: &str) -> TestResult {
        self.batches += 1;
        let index = self.batches;
        let mut deployment = ReferenceDeployment::open(&self.root, SITE, &self.cx)?;
        let payload = deployment.stage_payload(format!("{family}-{index}").as_bytes())?;
        deployment.append_batch(
            BatchId::parse(format!("batch:follow-unit:{index}"))?,
            vec![EvidenceDelta {
                delta_id: format!("delta:follow-unit:{index}"),
                family: family.to_owned(),
                object_id: ObjectId::parse(format!("object:follow-unit:{index}"))?,
                prior_generation: None,
                new_generation: 1,
                validity: CaptureInterval::new(TimestampNs(1_000), TimestampNs(1_500))?,
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

    fn history(&self) -> Result<DeploymentHistory, DeploymentReadError> {
        DeploymentHistory::read(&self.root, &OrientLimits::default())
    }

    fn head_token(&self) -> TestResult<AnchorToken> {
        let snapshot = read_deployment(&self.root, &OrientLimits::default())?;
        Ok(AnchorToken::parse(&snapshot_anchor_token(&snapshot)).ok_or("head token parses")?)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn request(view: AgentView, max_entries: u32) -> TestResult<FollowRequest> {
    Ok(FollowRequest {
        view,
        principal: PrincipalId::parse("principal:follow-unit")?,
        max_entries,
        continuation: None,
    })
}

#[test]
fn anchor_tokens_parse_only_their_canonical_spelling() {
    let binding = "ab".repeat(32);
    let good = format!("anchor:0123456789abcdef:7:e3:{binding}");
    let parsed = AnchorToken::parse(&good);
    assert_eq!(
        parsed.as_ref().map(AnchorToken::position),
        Some(HistoryPosition {
            commit_sequence: 7,
            effect_records: Some(3),
        })
    );
    assert_eq!(
        parsed.as_ref().map(AnchorToken::as_str),
        Some(good.as_str())
    );
    let none = format!("anchor:0123456789abcdef:0:none:{binding}");
    assert_eq!(
        AnchorToken::parse(&none).map(|token| token.position().effect_records),
        Some(None)
    );
    for bad in [
        format!("anchor:0123456789abcdef:07:e3:{binding}"),
        format!("anchor:0123456789abcdef:7:e03:{binding}"),
        format!("anchor:0123456789ABCDEF:7:e3:{binding}"),
        format!("anchor:0123456789abcdef:7:3:{binding}"),
        format!("anchor:0123456789abcdef:7:e3:{}", "ab".repeat(31)),
        format!("anchor:0123456789abcdef:7:e3:{binding}:extra"),
        format!("anchor:0123456789abcdef:+7:e3:{binding}"),
        format!("anchor:0123456789abcde:7:e3:{binding}"),
        format!("anchor:0123456789abcdef:7:{binding}"),
        format!("0123456789abcdef:7:e3:{binding}"),
        String::new(),
    ] {
        assert_eq!(AnchorToken::parse(&bad), None, "{bad}");
    }
}

#[test]
fn as_of_snapshots_reproduce_every_earlier_head_exactly() -> TestResult {
    let mut fixture = Fixture::new("as-of")?;
    let limits = OrientLimits::default();
    let mut heads = vec![read_deployment(&fixture.root, &limits)?];
    for _ in 0..3 {
        fixture.commit()?;
        heads.push(read_deployment(&fixture.root, &limits)?);
    }
    let history = fixture.history()?;
    assert_eq!(history.head(), heads[3].position);
    let request = OrientRequest {
        view: AgentView::Brief,
        principal: PrincipalId::parse("principal:follow-unit")?,
        budget_tokens: None,
    };
    for (commit, earlier) in heads.iter().enumerate() {
        assert_eq!(earlier.position.commit_sequence, commit as u64);
        assert_eq!(earlier.batch_count, commit);
        let as_of = history.snapshot_at(earlier.position)?;
        // The doctor verdict (like the tail flags) classifies the files as read now, not the
        // prefix: it is the one documented field an as-of read takes from the current root.
        assert_eq!(as_of.doctor_verdict, heads[3].doctor_verdict);
        let mut earlier = earlier.clone();
        earlier.doctor_verdict = as_of.doctor_verdict;
        // Reading only the prefix reproduces every other field of the snapshot the head read
        // produced at that time (read accounting, digests, anchors, events, effects) ...
        assert_eq!(as_of, earlier);
        // ... and therefore the same orientation, down to its publication digest and token.
        let then = orient_deployment(&earlier, &request, &limits)?;
        let now = orient_deployment(&as_of, &request, &limits)?;
        assert_eq!(
            then.publication.publication_digest,
            now.publication.publication_digest
        );
        assert_eq!(then.anchor_token, snapshot_anchor_token(&earlier));
    }
    // A position the history never committed is refused, not approximated.
    let beyond = HistoryPosition {
        commit_sequence: 4,
        effect_records: heads[3].position.effect_records,
    };
    assert!(!history.contains(beyond));
    assert!(matches!(
        history.snapshot_at(beyond),
        Err(DeploymentReadError::NotCommitted { .. })
    ));
    Ok(())
}

#[test]
fn anchor_resolution_refuses_foreign_ahead_and_unknown_tokens() -> TestResult {
    let mut fixture = Fixture::new("resolve")?;
    let first = fixture.head_token()?;
    fixture.commit()?;
    let history = fixture.history()?;
    assert_eq!(resolve_anchor(&history, &first), Ok(first.position()));
    let head = fixture.head_token()?;
    assert_eq!(resolve_anchor(&history, &head), Ok(history.head()));

    let rewrite = |site: Option<&str>, commit: Option<u64>, binding: Option<&str>| {
        let text = first.as_str();
        let parts: Vec<&str> = text.split(':').collect();
        let commit = commit.map(|value| value.to_string());
        let token = format!(
            "anchor:{}:{}:{}:{}",
            site.unwrap_or(parts[1]),
            commit.as_deref().unwrap_or(parts[2]),
            parts[3],
            binding.unwrap_or(parts[4])
        );
        AnchorToken::parse(&token).ok_or("rewritten token parses")
    };
    assert_eq!(
        resolve_anchor(&history, &rewrite(Some("0000000000000000"), None, None)?),
        Err(AnchorRefusal::Foreign)
    );
    assert_eq!(
        resolve_anchor(&history, &rewrite(None, Some(9), None)?),
        Err(AnchorRefusal::Ahead)
    );
    let tampered = "0".repeat(64);
    assert_eq!(
        resolve_anchor(&history, &rewrite(None, None, Some(&tampered))?),
        Err(AnchorRefusal::Unknown)
    );
    // The first token's binding is not the binding of the next commit.
    assert_eq!(
        resolve_anchor(&history, &rewrite(None, Some(1), None)?),
        Err(AnchorRefusal::Unknown)
    );
    // Effect records beyond the committed journal are ahead of the head.
    if let Some(records) = history.head().effect_records {
        let parts: Vec<&str> = first.as_str().split(':').collect();
        let ahead = format!(
            "anchor:{}:{}:e{}:{}",
            parts[1],
            parts[2],
            records + 1,
            parts[4]
        );
        let ahead = AnchorToken::parse(&ahead).ok_or("ahead token parses")?;
        assert_eq!(resolve_anchor(&history, &ahead), Err(AnchorRefusal::Ahead));
    }
    Ok(())
}

#[test]
fn follow_since_an_earlier_anchor_reports_the_committed_change() -> TestResult {
    let mut fixture = Fixture::new("change")?;
    let limits = OrientLimits::default();
    let before = read_deployment(&fixture.root, &limits)?;
    let since = AnchorToken::parse(&snapshot_anchor_token(&before)).ok_or("token")?;
    fixture.commit()?;
    let history = fixture.history()?;
    let follow = follow_deployment(&history, &since, &request(AgentView::Brief, 4096)?)?;

    // The basis is the orientation that was current at the anchor, under the doctor verdict of
    // the root as read now (the one field an as-of read takes from the current files).
    let mut before = before;
    before.doctor_verdict = read_deployment(&fixture.root, &limits)?.doctor_verdict;
    let then = orient_deployment(
        &before,
        &OrientRequest {
            view: AgentView::Brief,
            principal: PrincipalId::parse("principal:follow-unit")?,
            budget_tokens: None,
        },
        &limits,
    )?;
    assert_eq!(
        follow.basis.publication.publication_digest,
        then.publication.publication_digest
    );
    assert_eq!(follow.basis.anchor_token, since.as_str());
    assert_eq!(follow.delta.basis_anchor.commit_sequence, 0);
    assert_eq!(follow.delta.result_anchor.commit_sequence, 1);
    assert!(
        follow
            .delta
            .classes
            .contains(&MeaningfulDeltaClass::MaterialState)
    );
    assert!(
        follow
            .delta
            .classes
            .contains(&MeaningfulDeltaClass::CoverageLoss)
    );
    assert!(follow.delta.silence_certificate.is_none());
    // anchor_position_restatement: the ledger-head cell restates the anchor, which the delta carries typed as its
    // result anchor, so the restatement alone is never a changed cell; the result still states it.
    assert!(
        !follow
            .delta
            .changed_cells
            .iter()
            .any(|cell| cell.claim_id() == CLAIM_LEDGER_HEAD)
    );
    let head_cell = follow
        .result
        .publication
        .situation
        .capsule
        .frame
        .knowledge_cells
        .iter()
        .find(|cell| cell.claim_id() == CLAIM_LEDGER_HEAD)
        .ok_or("the result states the ledger head")?;
    assert!(
        head_cell.statement().contains("at commit 1"),
        "{}",
        head_cell.statement()
    );
    // One page carries every item, protected ones first.
    assert_eq!(follow.page_items, follow.items);
    assert!(follow.page.next_cursor.is_none());
    let first_plain = follow
        .items
        .iter()
        .position(|item| !item.critical())
        .unwrap_or(follow.items.len());
    assert!(
        follow.items[first_plain..]
            .iter()
            .all(|item| !item.critical())
    );

    // Deterministic: the same committed bytes yield the same follow.
    let again = follow_deployment(&history, &since, &request(AgentView::Brief, 4096)?)?;
    assert_eq!(again, follow);
    Ok(())
}

#[test]
fn follow_since_the_head_keeps_the_persisting_coverage_gap_protected() -> TestResult {
    let mut fixture = Fixture::new("head")?;
    fixture.commit()?;
    let history = fixture.history()?;
    let head = fixture.head_token()?;
    let follow = follow_deployment(
        &history,
        &head,
        &request(AgentView::Brief, DEFAULT_FOLLOW_MAX_ENTRIES)?,
    )?;
    assert_eq!(
        follow.basis.publication.publication_digest,
        follow.result.publication.publication_digest
    );
    // Nothing committed changed, but no CoverageWitness is retained: the engine keeps the gap as
    // protected coverage loss and certifies no silence.
    assert_eq!(
        follow.delta.classes,
        BTreeSet::from([MeaningfulDeltaClass::CoverageLoss])
    );
    assert!(follow.delta.silence_certificate.is_none());
    assert!(follow.delta.changed_cells.is_empty());
    assert!(follow.delta.removed_claim_ids.is_empty());
    assert!(follow.delta.obligation_changes.is_empty());
    assert!(follow.delta.effect_uncertainty_changes.is_empty());
    assert!(!follow.items.is_empty());
    assert!(
        follow
            .items
            .iter()
            .all(|item| matches!(item, FollowItem::Coverage(_)) && item.critical())
    );
    Ok(())
}

#[test]
fn pages_deliver_every_item_once_through_bound_continuations() -> TestResult {
    let mut fixture = Fixture::new("pages")?;
    let limits = OrientLimits::default();
    let since = AnchorToken::parse(&snapshot_anchor_token(&read_deployment(
        &fixture.root,
        &limits,
    )?))
    .ok_or("token")?;
    fixture.commit()?;
    fixture.commit()?;
    let history = fixture.history()?;
    let complete = follow_deployment(&history, &since, &request(AgentView::Brief, 4096)?)?;
    assert!(complete.items.len() > 2, "{:?}", complete.items);

    let mut paged = request(AgentView::Brief, 2)?;
    let mut delivered = Vec::new();
    let mut tokens = Vec::new();
    loop {
        let page = follow_deployment(&history, &since, &paged)?;
        assert_eq!(page.delta, complete.delta, "every page is the same delta");
        assert_eq!(page.stream.source_digest, {
            let first = follow_deployment(&history, &since, &request(AgentView::Brief, 2)?)?;
            first.stream.source_digest
        });
        assert!(page.page_items.len() <= 2);
        assert_eq!(page.page_start(), delivered.len() as u64);
        page.page.verify()?;
        delivered.extend(page.page_items.clone());
        match page.page.next_cursor {
            Some(next) => {
                tokens.push(next.token().to_owned());
                paged.continuation = Some(next.token().to_owned());
            }
            None => break,
        }
    }
    assert_eq!(delivered, complete.items, "no item is dropped or repeated");
    assert!(!tokens.is_empty());

    // Replaying a cursor returns the same page.
    let replay = follow_deployment(&history, &since, &paged)?;
    assert_eq!(
        replay.page.page_digest,
        follow_deployment(&history, &since, &paged)?
            .page
            .page_digest
    );

    let refused = |continuation: String, view: AgentView, max_entries: u32| -> TestResult<bool> {
        let mut attempt = request(view, max_entries)?;
        attempt.continuation = Some(continuation);
        Ok(matches!(
            follow_deployment(&history, &since, &attempt),
            Err(FollowError::Continuation(ContinuationError::WrongStream))
        ))
    };
    let token = tokens[0].clone();
    let mut tampered = token.clone();
    let last = tampered.pop().ok_or("token is non-empty")?;
    tampered.push(if last == '0' { '1' } else { '0' });
    assert!(refused(tampered, AgentView::Brief, 2)?);
    // The same cursor token is bound to its view and page size.
    assert!(refused(token.clone(), AgentView::Pulse, 2)?);
    assert!(refused(token.clone(), AgentView::Brief, 3)?);
    // A cursor issued before the head advanced is refused: the stream it belongs to is gone.
    fixture.commit()?;
    let advanced = fixture.history()?;
    let mut stale = request(AgentView::Brief, 2)?;
    stale.continuation = Some(token);
    assert!(matches!(
        follow_deployment(&advanced, &since, &stale),
        Err(FollowError::Continuation(ContinuationError::WrongStream))
    ));
    Ok(())
}

#[test]
fn a_harmless_successor_commit_changes_no_decision_semantics() -> TestResult {
    let mut fixture = Fixture::new("harmless")?;
    fixture.commit()?;
    fixture.commit_import()?;
    let since = fixture.head_token()?;
    // A derived receipt over already-committed evidence advances the ledger head only.
    fixture.commit_derived()?;
    let history = fixture.history()?;
    let follow = follow_deployment(&history, &since, &request(AgentView::Brief, 4096)?)?;
    assert_eq!(follow.delta.basis_anchor.commit_sequence, 2);
    assert_eq!(follow.delta.result_anchor.commit_sequence, 3);
    assert_ne!(
        follow.basis.publication.publication_digest, follow.result.publication.publication_digest,
        "the head advanced"
    );
    // Nothing decision-relevant changed: no changed cell (the ledger-head restatement is
    // anchor_position_restatement), no material state (the re-priced affordances are affordance_cost_repricing), no removal. Without a
    // retained CoverageWitness the persisting gap stays protected coverage loss, exactly as it is
    // when basis and result are one anchor.
    assert_eq!(
        follow.delta.classes,
        BTreeSet::from([MeaningfulDeltaClass::CoverageLoss])
    );
    assert!(follow.delta.changed_cells.is_empty());
    assert!(follow.delta.removed_claim_ids.is_empty());
    assert!(follow.delta.invalidated_assumptions.is_empty());
    assert!(follow.delta.silence_certificate.is_none());
    // A source-evidence commit, by contrast, is material.
    fixture.commit()?;
    let history = fixture.history()?;
    let material = follow_deployment(&history, &since, &request(AgentView::Brief, 4096)?)?;
    assert!(
        material
            .delta
            .classes
            .contains(&MeaningfulDeltaClass::MaterialState)
    );
    Ok(())
}
