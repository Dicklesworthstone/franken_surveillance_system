#![forbid(unsafe_code)]
//! Fresh export previews against real retained event authority and an active writer.

use super::*;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fss_cli::json_input::{Value, parse as parse_json};
use fss_core::region::ContextNarrowingSpec;
use fss_core::{
    CanonicalEncode, CaptureInterval, DecisionPath, EventEvidence, EventHypothesis, EventKind,
    EventState, EvidenceClass, EvidenceEdgeRelation, ProbabilityInterval,
};
use fss_reference::{ReferencePolicyAction, ReferencePolicyDecision};

type Test<T = ()> = Result<T, Box<dyn Error>>;
const SITE: &str = "site:immutable-export-preview";
const ACTOR: &str = "principal:immutable-export-preview";
const SOURCE: &[u8] = b"private synthetic source payload";
const MODEL: &[u8] = b"private synthetic model payload";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-export-preview-{label}-{}-{attempt}",
                std::process::id(),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("temporary directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    deployment: ReferenceDeployment,
    cx: ReplayCx,
    authority: ContextAuthority,
    event: EventHypothesis,
    directory: Directory,
}
impl Fixture {
    fn new(label: &str) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:immutable-export-preview".into(),
            operation_id: OperationId::parse("operation:immutable-export-preview")?,
            principal: ACTOR.into(),
            capabilities: vec![
                "ADP-REPLAY-001".into(),
                CAP_EXPORT_PREPARE.into(),
                CAP_EXPORT_COMMIT.into(),
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
            event_id: EventId::parse("event:immutable-export-preview")?,
            revision: 1,
            supersedes: None,
            state: EventState::Indeterminate,
            kind: EventKind::Unclassified,
            interval: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
            uncertainty_reason: Some("Synthetic fixture".into()),
            zone_ids: vec!["private-zone-name".into()],
            track_ids: vec!["private-track-name".into()],
            probability: ProbabilityInterval::new(0.0, 1.0)?,
            evidence: vec![EventEvidence {
                digest: ContentDigest::sha256(SOURCE),
                class: EvidenceClass::Assertion,
                failure_domain: "sensor:private-front-door".into(),
                supports: false,
                relation: EvidenceEdgeRelation::DerivedFrom,
                capsule_digest: None,
                identity_digest: Some(ContentDigest::sha256(b"private identity")),
            }],
            model_receipts: vec![ContentDigest::sha256(MODEL)],
            decision_path: DecisionPath {
                policy_generation: ContentDigest::sha256(b"synthetic policy"),
                fingerprint: ContentDigest::sha256(b"synthetic decision"),
                abstained: true,
                abstention_reason: Some("Synthetic fixture".into()),
            },
        };
        deployment.stage_payload(SOURCE)?;
        deployment.stage_payload(MODEL)?;
        deployment.publish_event(
            &ReferencePolicyDecision {
                event: event.clone(),
                action: ReferencePolicyAction::Hold,
            },
            &cx,
        )?;
        Ok(Self {
            deployment,
            cx,
            authority,
            event,
            directory,
        })
    }

    fn args(&self) -> Vec<OsString> {
        vec![
            "event".into(),
            "--root".into(),
            self.deployment.root().as_os_str().to_owned(),
            "--site".into(),
            SITE.into(),
            "--principal".into(),
            ACTOR.into(),
            "--event-id".into(),
            self.event.event_id.as_str().into(),
            "--expected-revision".into(),
            self.event.revision_digest().to_text().into(),
            "--recipient".into(),
            "recipient:owner-case-7".into(),
            "--purpose".into(),
            "Owner-authorized incident review".into(),
            "--expires-at-ns".into(),
            "100".into(),
        ]
    }
    fn options(&self) -> Test<Options> {
        Ok(parse(&self.args())?)
    }
}

// Include directories and exact file bytes: even an empty lock/recovery entry is a mutation.
fn tree(root: &Path) -> Test<BTreeMap<PathBuf, Option<Vec<u8>>>> {
    fn visit(root: &Path, path: &Path, entries: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) -> Test {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            let name = path.strip_prefix(root)?.to_path_buf();
            if entry.file_type()?.is_dir() {
                entries.insert(name, None);
                visit(root, &path, entries)?;
            } else {
                entries.insert(name, Some(fs::read(path)?));
            }
        }
        Ok(())
    }
    let mut entries = BTreeMap::new();
    visit(root, root, &mut entries)?;
    Ok(entries)
}

fn field<'a>(value: &'a Value, name: &str) -> Test<&'a Value> {
    Ok(value
        .object()
        .and_then(|fields| fields.get(name))
        .ok_or("report field")?)
}

#[test]
fn active_writer_preview_matches_native_report_without_opening_source_or_model_payloads() -> Test {
    let f = Fixture::new("native-parity")?;
    let options = f.options()?;
    let native = preview_export(&f.deployment, &options.request, &f.authority, &f.cx)?;
    let expected = event_report(&options, &native, false, f.deployment.current_anchor())?;
    let before = tree(f.deployment.root())?;
    assert_eq!(run(&options)?, expected);
    assert_eq!(tree(f.deployment.root())?, before);
    for private in [
        "private-zone-name",
        "private-track-name",
        "sensor:private-front-door",
        "private identity",
        "private synthetic",
    ] {
        assert!(!expected.contains(private), "leaked {private}");
    }
    assert!(expected.contains("\"raw_media_read\":false"));
    assert!(expected.contains("\"external_transport_performed\":false"));
    for bytes in [SOURCE, MODEL] {
        fs::remove_file(
            f.deployment
                .publisher()
                .spool()
                .object_path(ContentDigest::sha256(bytes)),
        )?;
    }
    let before = tree(f.deployment.root())?;
    assert_eq!(run(&options)?, expected);
    assert_eq!(tree(f.deployment.root())?, before);
    let denied = f.authority.narrow(ContextNarrowingSpec {
        operation_id: OperationId::parse("operation:immutable-export-preview-denied")?,
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: f.authority.deadline,
        priority: f.authority.priority,
        budgets: f.authority.budgets,
        privacy_scope: f.authority.privacy_scope.clone(),
        retention_scope: f.authority.retention_scope.clone(),
        lease_fence: None,
        idempotency_key: None,
        lab_controls: None,
    })?;
    let error = run_preview_with(&options, &denied, &f.cx, &|| false)
        .err()
        .ok_or("unauthorized preview succeeded")?;
    assert!(matches!(
        error.downcast_ref::<ExportError>(),
        Some(ExportError::Unauthorized)
    ));
    assert_eq!(tree(f.deployment.root())?, before);
    Ok(())
}

#[test]
fn exact_preview_approval_still_requires_the_writer_and_commits_after_its_release() -> Test {
    let f = Fixture::new("approval")?;
    let preview_options = f.options()?;
    let proposed = parse_json(&run(&preview_options)?)?;
    let approval = ContentDigest::parse(
        field(&proposed, "approval_digest")?
            .text()
            .ok_or("approval text")?,
    )?;
    let mut approved = f.options()?;
    approved.approval = Some(approval);
    let root = f.deployment.root().to_path_buf();
    let before = tree(&root)?;
    assert!(
        run(&approved).is_err(),
        "approved export acquired an occupied writer"
    );
    assert_eq!(tree(&root)?, before);
    drop(f.deployment);
    let published = parse_json(&run(&approved)?)?;
    assert_eq!(field(&published, "status")?.text(), Some("published"));
    assert_eq!(field(&published, "published")?.boolean(), Some(true));
    for name in ["approval_digest", "export_root", "record_digest", "package"] {
        assert_eq!(
            field(&published, name)?,
            field(&proposed, name)?,
            "changed {name}"
        );
    }
    let committed = tree(&root)?;
    let retry = parse_json(&run(&approved)?)?;
    assert_eq!(field(&retry, "status")?.text(), Some("already_committed"));
    assert_eq!(field(&retry, "published")?.boolean(), Some(false));
    let reread = parse_json(&run(&preview_options)?)?;
    assert_eq!(field(&reread, "status")?.text(), Some("already_committed"));
    assert_eq!(
        field(&reread, "approval_digest")?,
        field(&proposed, "approval_digest")?
    );
    assert_eq!(tree(&root)?, committed);
    Ok(())
}

#[test]
fn complete_preview_budget_includes_final_snapshot_and_selected_payload_rereads() -> Test {
    let f = Fixture::new("budget")?;
    let mut options = f.options()?;
    let before = tree(f.deployment.root())?;
    // Measure real native work independently of the CLI's delivery wrapper. The allowance
    // must admit both complete final phases, not merely the initial event projection.
    let source = ImmutableRetainedSource::open(f.deployment.root(), options.read_limits, &f.cx)?;
    let preview = preview_export(&source, &options.request, &f.authority, &f.cx)?;
    let expected = event_report(&options, &preview, false, &source.snapshot().anchor)?;
    let projected = source.usage();
    source.revalidate_snapshot_metadata()?;
    let metadata = source.usage();
    source.revalidate()?;
    let complete = source.usage();
    assert!(
        metadata.read_bytes > projected.read_bytes
            && metadata.read_objects > projected.read_objects
    );
    assert!(
        complete.read_bytes > metadata.read_bytes && complete.read_objects > metadata.read_objects
    );
    drop(source);
    options.read_limits.max_read_bytes = usize::try_from(complete.read_bytes)?;
    options.read_limits.max_read_objects = usize::try_from(complete.read_objects)?;
    assert_eq!(run(&options)?, expected);
    let exact = options.read_limits;
    for bytes_short in [true, false] {
        options.read_limits = exact;
        if bytes_short {
            options.read_limits.max_read_bytes -= 1;
        } else {
            options.read_limits.max_read_objects -= 1;
        }
        assert!(
            run(&options).is_err(),
            "incomplete final allowance returned a report"
        );
    }
    assert_eq!(tree(f.deployment.root())?, before);
    Ok(())
}

#[test]
fn late_canonical_event_damage_refuses_the_buffered_preview_without_repair() -> Test {
    let f = Fixture::new("late-event")?;
    let options = f.options()?;
    let path = f
        .deployment
        .publisher()
        .spool()
        .object_path(ContentDigest::sha256(&f.event.canonical_bytes()));
    let original = fs::read(&path)?;
    let calls = AtomicUsize::new(0);
    let admission = || {
        calls.fetch_add(1, Ordering::SeqCst);
        false
    };
    let source = ImmutableRetainedSource::open_cancellable(
        f.deployment.root(),
        options.read_limits,
        &f.cx,
        &admission,
    )?;
    let native = preview_export(&source, &options.request, &f.authority, &f.cx)?;
    let expected = event_report(&options, &native, false, &source.snapshot().anchor)?;
    let delivery_boundary = calls.load(Ordering::SeqCst) + 1;
    drop(source);
    let mut damaged = original.clone();
    damaged[0] ^= 1;
    let changed = AtomicBool::new(false);
    calls.store(0, Ordering::SeqCst);
    let result = run_preview_with(&options, &f.authority, &f.cx, &|| {
        if calls.fetch_add(1, Ordering::SeqCst) + 1 == delivery_boundary {
            changed.store(fs::write(&path, &damaged).is_ok(), Ordering::SeqCst);
        }
        false
    });
    assert!(
        changed.load(Ordering::SeqCst),
        "late custody change was not injected"
    );
    assert!(
        result.is_err(),
        "changed event metadata released a buffered approval"
    );
    assert_eq!(
        fs::read(&path)?,
        damaged,
        "preview repaired damaged custody"
    );
    let after = tree(f.deployment.root())?;
    assert!(run(&options).is_err());
    assert_eq!(tree(f.deployment.root())?, after);
    fs::write(path, original)?;
    assert_eq!(run(&options)?, expected);
    Ok(())
}

#[test]
fn missing_torn_and_foreign_state_refuse_without_repair_or_initialization() -> Test {
    let f = Fixture::new("state-refusal")?;
    let options = f.options()?;
    for relative in ["ledger/journal.fssj", "effects/journal.fssj"] {
        let path = f.deployment.root().join(relative);
        let original = fs::read(&path)?;
        let mut torn = original.clone();
        torn.extend_from_slice(b"FSS");
        fs::write(&path, torn)?;
        let before = tree(f.deployment.root())?;
        assert!(run(&options).is_err(), "accepted torn {relative}");
        assert_eq!(tree(f.deployment.root())?, before, "repaired {relative}");
        fs::remove_file(&path)?;
        let before = tree(f.deployment.root())?;
        assert!(run(&options).is_err(), "accepted missing {relative}");
        assert_eq!(tree(f.deployment.root())?, before, "recreated {relative}");
        fs::write(path, original)?;
    }
    let before = tree(f.deployment.root())?;
    let mut foreign = f.options()?;
    foreign.site = "site:foreign-export-preview".into();
    assert!(run(&foreign).is_err());
    assert_eq!(tree(f.deployment.root())?, before);
    let mut missing = f.options()?;
    let absent = f.directory.0.join("absent-deployment");
    missing.root = absent.clone();
    let before = tree(&f.directory.0)?;
    assert!(run(&missing).is_err());
    assert!(!absent.exists());
    assert_eq!(tree(&f.directory.0)?, before);
    Ok(())
}

#[test]
fn immediate_final_boundary_and_deadline_cancellation_release_no_preview() -> Test {
    let f = Fixture::new("cancellation")?;
    let mut options = f.options()?;
    let before = tree(f.deployment.root())?;
    let error = run_preview_with(&options, &f.authority, &f.cx, &|| true)
        .err()
        .ok_or("cancelled preview succeeded")?;
    assert!(matches!(
        error.downcast_ref::<ExportError>(),
        Some(ExportError::Cancelled)
    ));
    let calls = AtomicUsize::new(0);
    let expected = run_preview_with(&options, &f.authority, &f.cx, &|| {
        calls.fetch_add(1, Ordering::SeqCst);
        false
    })?;
    let final_boundary = calls.load(Ordering::SeqCst);
    assert!(final_boundary > 1);
    calls.store(0, Ordering::SeqCst);
    let error = run_preview_with(&options, &f.authority, &f.cx, &|| {
        calls.fetch_add(1, Ordering::SeqCst) + 1 >= final_boundary
    })
    .err()
    .ok_or("final cancellation released a report")?;
    assert!(matches!(
        error.downcast_ref::<ExportError>(),
        Some(ExportError::Cancelled)
    ));
    assert_eq!(run(&options)?, expected);
    options.timeout = Duration::ZERO;
    assert!(run(&options).is_err(), "expired deadline returned a report");
    options.approval = Some(ContentDigest::sha256(b"not an immutable operation"));
    let error = run_preview_with(&options, &f.authority, &f.cx, &|| false)
        .err()
        .ok_or("immutable helper accepted publication")?;
    assert!(matches!(
        error.downcast_ref::<ExportError>(),
        Some(ExportError::Unauthorized)
    ));
    assert_eq!(tree(f.deployment.root())?, before);
    Ok(())
}

#[test]
fn read_options_are_canonical_bounded_and_cannot_change_approved_publication() -> Test {
    let f = Fixture::new("parse-limits")?;
    let before = tree(f.deployment.root())?;
    for (key, maximum) in [
        ("--max-read-bytes", MAX_SHOW_READ_BYTES),
        ("--max-read-objects", MAX_SHOW_READ_OBJECTS),
        ("--timeout-ms", 600_000),
    ] {
        for value in [
            "0".into(),
            "-1".into(),
            "+1".into(),
            "01".into(),
            (maximum + 1).to_string(),
            "18446744073709551616".into(),
        ] {
            let mut args = f.args();
            args.extend([OsString::from(key), OsString::from(value)]);
            assert!(parse(&args).is_err(), "accepted {key}");
        }
        let mut args = f.args();
        args.extend([OsString::from(key), OsString::from(maximum.to_string())]);
        assert!(parse(&args).is_ok());
        args.extend([
            "--approve".into(),
            ContentDigest::sha256(b"approval").to_text().into(),
        ]);
        assert!(
            parse(&args).is_err(),
            "preview limit changed approved semantics"
        );
    }
    assert_eq!(tree(f.deployment.root())?, before);
    Ok(())
}
