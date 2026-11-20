#![forbid(unsafe_code)]
//! Actual retained review authority with a live publisher, including complete delivery checks.

use super::*;
use std::path::Path;

use fss_core::{
    CaptureInterval, DecisionPath, EffectIntent, EventEvidence, EventHypothesis, EventKind,
    EventState, EvidenceClass, EvidenceEdgeRelation, IdempotencyKey, ObligationId,
    ProbabilityInterval, TimestampNs,
};
use fss_reference::{ReferencePolicyAction, ReferencePolicyDecision};

type Test<T = ()> = Result<T, Box<dyn Error>>;
const SITE: &str = "site:immutable-review";
const PRINCIPAL: &str = "principal:immutable-review";

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    deployment: ReferenceDeployment,
    authority: ContextAuthority,
    cx: ReplayCx,
    event: EventHypothesis,
    _directory: Directory,
}
impl Fixture {
    fn new(label: &str) -> Test<Self> {
        let mut directory = None;
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-immutable-review-{label}-{}-{attempt}",
                std::process::id(),
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    directory = Some(Directory(path));
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        let directory = directory.ok_or("temporary directory capacity")?;
        let root = directory.0.join("deployment");
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:immutable-review".into(),
            operation_id: OperationId::parse("operation:immutable-review")?,
            principal: PRINCIPAL.into(),
            capabilities: vec![
                "ADP-REPLAY-001".into(),
                CAP_REVIEW_PREPARE.into(),
                CAP_REVIEW_COMMIT.into(),
            ],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(1024 * 1024 * 1024)
                .storage_operations(1_000_000)
                .build()?,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
            generation: 1,
        })?;
        let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let event = EventHypothesis {
            schema: EventHypothesis::SCHEMA.into(),
            event_id: EventId::parse("event:immutable-review")?,
            revision: 1,
            supersedes: None,
            state: EventState::Indeterminate,
            kind: EventKind::Unclassified,
            interval: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
            uncertainty_reason: Some(
                "Synthetic fixture; sensor integrity remains unresolved".into(),
            ),
            zone_ids: vec!["door".into()],
            track_ids: vec!["track:synthetic".into()],
            probability: ProbabilityInterval::new(0.0, 1.0)?,
            evidence: vec![EventEvidence {
                digest: ContentDigest::sha256(b"synthetic source assertion"),
                class: EvidenceClass::Assertion,
                failure_domain: "synthetic-source".into(),
                supports: false,
                relation: EvidenceEdgeRelation::SensorTamper,
                capsule_digest: None,
                identity_digest: Some(ContentDigest::sha256(b"synthetic-source")),
            }],
            model_receipts: Vec::new(),
            decision_path: DecisionPath {
                policy_generation: ContentDigest::sha256(b"synthetic policy"),
                fingerprint: ContentDigest::sha256(b"synthetic decision"),
                abstained: true,
                abstention_reason: Some("Synthetic unclassified fixture".into()),
            },
        };
        deployment.stage_payload(b"synthetic source assertion")?;
        deployment.publish_event(
            &ReferencePolicyDecision {
                event: event.clone(),
                action: ReferencePolicyAction::Hold,
            },
            &cx,
        )?;
        Ok(Self {
            deployment,
            authority,
            cx,
            event,
            _directory: directory,
        })
    }

    fn options(&self, action: &str) -> Test<Options> {
        let mut args: Vec<OsString> = vec![
            action.into(),
            "--root".into(),
            self.deployment.root().as_os_str().to_owned(),
            "--site".into(),
            SITE.into(),
            "--principal".into(),
            PRINCIPAL.into(),
            "--event-id".into(),
            self.event.event_id.as_str().into(),
        ];
        if action != "show" {
            args.extend([
                "--expected-revision".into(),
                self.event.revision_digest().to_text().into(),
                "--reason".into(),
                "Owner reviewed available evidence".into(),
            ]);
        }
        Ok(parse(&args)?)
    }

    fn commit(&mut self, options: &Options) -> Test<ReviewPreview> {
        let request = options.request.as_ref().ok_or("review request")?;
        let preview = preview_review(&self.deployment, request, &self.authority, &self.cx)?;
        Ok(commit_review(
            &mut self.deployment,
            request,
            preview.approval(),
            &self.authority,
            &self.cx,
        )?
        .review)
    }

    fn prepare_effect(&mut self) -> Test {
        let intent = EffectIntent::new(
            OperationId::parse("operation:unrelated-immutable-review")?,
            IdempotencyKey::parse("idempotency:unrelated-immutable-review")?,
            "test.review-boundary",
            ContentDigest::sha256(b"synthetic request"),
            ContentDigest::sha256(b"synthetic precondition"),
        )?;
        self.deployment.effects_mut().prepare(
            intent,
            ObligationId::parse("obligation:unrelated-immutable-review")?,
            "test-only pending work; no transport",
            TimestampNs(100),
        )?;
        Ok(())
    }
}

fn tree(root: &Path) -> Test<BTreeMap<PathBuf, Option<Vec<u8>>>> {
    fn visit(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) -> Test {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            let name = path.strip_prefix(root)?.to_path_buf();
            if entry.file_type()?.is_dir() {
                result.insert(name, None);
                visit(root, &path, result)?;
            } else {
                result.insert(name, Some(fs::read(path)?));
            }
        }
        Ok(())
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result)?;
    Ok(result)
}

#[test]
fn active_writer_show_and_preview_preserve_exact_json_approval_and_tamper_history() -> Test {
    let f = Fixture::new("live-writer")?;
    let before = tree(f.deployment.root())?;
    for action in ["show", "investigate", "resolve", "reject"] {
        let options = f.options(action)?;
        let expected = render_read(&options, &f.deployment, &f.authority, &f.cx)?;
        let actual = run(&options)?;
        assert_eq!(actual, expected, "{action}");
        if action == "show" {
            assert!(actual.contains("\"open_sensor_tamper\":true"));
        }
        assert_eq!(tree(f.deployment.root())?, before);
    }
    let mut denied = f.authority.clone();
    denied
        .capabilities
        .retain(|capability| capability != CAP_REVIEW_PREPARE);
    assert!(matches!(
        run_with(&f.options("show")?, &denied, &f.cx, &|| false)
            .unwrap_err()
            .downcast_ref::<ReviewError>(),
        Some(ReviewError::Unauthorized),
    ));
    assert_eq!(tree(f.deployment.root())?, before);
    Ok(())
}

#[test]
fn publication_remains_exclusive_and_exact_committed_retry_remains_read_only() -> Test {
    let f = Fixture::new("publication")?;
    let preview_options = f.options("resolve")?;
    let show_options = f.options("show")?;
    let preview = preview_review(
        &f.deployment,
        preview_options.request.as_ref().ok_or("request")?,
        &f.authority,
        &f.cx,
    )?;
    let mut approved = preview_options.clone();
    approved.approval = Some(preview.approval());
    let root = f.deployment.root().to_path_buf();
    let before = tree(&root)?;
    assert!(
        run(&approved).is_err(),
        "approved write acquired the live publisher"
    );
    assert_eq!(tree(&root)?, before);
    drop(f.deployment);
    assert!(run(&approved)?.contains("\"published\":true"));
    let committed = tree(&root)?;
    let shown = run(&show_options)?;
    assert!(shown.contains("verified_current_review"));
    assert!(shown.contains("\"open_sensor_tamper\":true"));
    let retry = run(&preview_options)?;
    assert!(retry.contains("\"status\":\"already_published\""));
    assert!(retry.contains(&preview.approval().to_text()));
    assert_eq!(tree(&root)?, committed);
    Ok(())
}

#[test]
fn final_delivery_spends_the_original_byte_and_attempt_allowances() -> Test {
    let f = Fixture::new("budget")?;
    let options = f.options("resolve")?;
    let before = tree(f.deployment.root())?;
    let (expected, used) = run_with(&options, &f.authority, &f.cx, &|| false)?;
    let mut exact = options.clone();
    exact.read_limits.max_read_bytes = usize::try_from(used.read_bytes)?;
    exact.read_limits.max_read_objects = usize::try_from(used.read_objects)?;
    let (actual, total) = run_with(&exact, &f.authority, &f.cx, &|| false)?;
    assert_eq!(actual, expected);
    assert_eq!(total, used);
    for bytes in [false, true] {
        let mut short = exact.clone();
        if bytes {
            short.read_limits.max_read_bytes -= 1;
        } else {
            short.read_limits.max_read_objects -= 1;
        }
        assert!(run_with(&short, &f.authority, &f.cx, &|| false).is_err());
    }
    assert_eq!(tree(f.deployment.root())?, before);
    Ok(())
}

#[test]
fn cancellation_at_the_buffered_delivery_boundary_returns_no_success() -> Test {
    let f = Fixture::new("final-cancel")?;
    let before = tree(f.deployment.root())?;
    f.cx.set_cancel_at_checkpoint("event_review_cli:delivery");
    assert!(run_with(&f.options("show")?, &f.authority, &f.cx, &|| false).is_err());
    assert!(f.cx.is_cancelled());
    assert_eq!(tree(f.deployment.root())?, before);
    Ok(())
}

#[test]
fn late_review_statement_damage_is_refused_without_repair() -> Test {
    let mut f = Fixture::new("custody")?;
    let options = f.options("reject")?;
    let review = f.commit(&options)?;
    let show = f.options("show")?;
    {
        // Compare the reconstructed receipt with the original operational owner, rather
        // than invoking the new generic helper twice. This successor has a real prior chain.
        let (expected_event, expected) = f.deployment.current_event_authority(&f.event.event_id)?;
        assert!(!expected.prior_revision_encodings.is_empty());
        let source =
            ImmutableRetainedSource::open(f.deployment.root(), options.read_limits, &f.cx)?;
        let (actual_event, actual) =
            read_review_event(&source, &f.event.event_id, &f.authority, &f.cx)?;
        assert_eq!(actual_event, expected_event);
        assert_eq!(actual.event_root, expected.event_root);
        assert_eq!(actual.event_object_digest, expected.event_object_digest);
        assert_eq!(actual.event_revision_digest, expected.event_revision_digest);
        assert_eq!(actual.authority_anchor, expected.authority_anchor);
        assert_eq!(actual.lineage_tamper_status, expected.lineage_tamper_status);
        assert_eq!(
            actual.prior_revision_encodings,
            expected.prior_revision_encodings
        );
        source.revalidate_snapshot_metadata()?;
        source.revalidate()?;
    }
    for digest in [
        review.record().digest(),
        review.provenance_root(),
        review.record().previous_event_root(),
    ] {
        let source =
            ImmutableRetainedSource::open(f.deployment.root(), options.read_limits, &f.cx)?;
        let _buffered = render_read(&show, &source, &f.authority, &f.cx)?;
        let path = f.deployment.publisher().spool().object_path(digest);
        let original = fs::read(&path)?;
        let mut changed = original.clone();
        *changed.last_mut().ok_or("empty retained object")? ^= 1;
        fs::write(&path, changed)?;
        let before = tree(f.deployment.root())?;
        assert!(
            source
                .revalidate_snapshot_metadata()
                .and_then(|()| source.revalidate())
                .is_err()
        );
        assert_eq!(tree(f.deployment.root())?, before);
        fs::write(path, original)?;
    }
    Ok(())
}

#[test]
fn effect_only_append_invalidates_delivery_and_blocks_new_reviews_but_not_exact_retries() -> Test {
    for committed in [false, true] {
        let mut f = Fixture::new(&format!("effect-{committed}"))?;
        let options = f.options("resolve")?;
        if committed {
            f.commit(&options)?;
        }
        let root = f.deployment.root().to_path_buf();
        let cx = ReplayCx::from_context_authority_read_only(&f.authority, root.clone())?;
        let source = ImmutableRetainedSource::open(&root, options.read_limits, &cx)?;
        let _buffered = render_read(&options, &source, &f.authority, &cx)?;
        let ledger = f.deployment.current_anchor().clone();
        f.prepare_effect()?;
        assert_eq!(
            f.deployment.current_anchor(),
            &ledger,
            "fixture must change only effects"
        );
        let before = tree(&root)?;
        assert!(
            source
                .revalidate_snapshot_metadata()
                .and_then(|()| source.revalidate())
                .is_err()
        );
        if committed {
            assert!(run(&options)?.contains("\"status\":\"already_published\""));
        } else {
            let error = run(&options).unwrap_err();
            assert!(matches!(
                error.downcast_ref::<ReviewError>(),
                Some(ReviewError::OpenEffects)
            ));
        }
        assert_eq!(tree(&root)?, before);
    }
    Ok(())
}

#[test]
fn missing_effect_history_never_authorizes_a_new_review_or_recreates_a_journal() -> Test {
    for committed in [false, true] {
        let mut f = Fixture::new(&format!("missing-effects-{committed}"))?;
        let options = f.options("reject")?;
        if committed {
            f.commit(&options)?;
        }
        let root = f.deployment.root().to_path_buf();
        fs::remove_file(root.join("effects/journal.fssj"))?;
        let before = tree(&root)?;
        assert!(run(&f.options("show")?).is_ok());
        if committed {
            assert!(run(&options)?.contains("\"status\":\"already_published\""));
        } else {
            let error = run(&options).unwrap_err();
            assert!(matches!(
                error.downcast_ref::<ReviewError>(),
                Some(ReviewError::CustodyMismatch)
            ));
        }
        assert_eq!(tree(&root)?, before);
        assert!(!root.join("effects/journal.fssj").exists());
    }
    Ok(())
}
