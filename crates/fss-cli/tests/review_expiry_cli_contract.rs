#![forbid(unsafe_code)]
//! Real CLI expiry cleanup over retained native review media, shared bytes and source holds.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_core::json_input::{self, Value};
use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, OperationId, PrincipalId,
    RootAuthoritySpec, SensorId, StreamId, TimestampNs,
};
use fss_reference::deletion::DeletionIndex;
use fss_reference::ingest::privacy_mask::current_mask;
use fss_reference::ingest::{
    FileIngestAdapter, FileIngestReceipt, FileIngestRequest, RetainedFileImport, RetainedReadLimits,
};
use fss_reference::review_media::grant::ReviewAccessRequest;
use fss_reference::review_media::render::{ReviewMovieLimits, ReviewMovieRequest};
use fss_reference::review_media::{
    ReviewMediaRecord, ReviewMediaRequest, commit_review_media, prepare_review_media,
    read_review_media,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn Error>>;
const SITE: &str = "site:review-expiry-cli";
const SENSOR: &str = "sensor:review-expiry-cli";
const OWNER: &str = "principal:local-operator";
const READER: &str = "principal:reviewer";
const EVENT: &str = env!("CARGO_BIN_EXE_fss-event");
const HOLD: &str = env!("CARGO_BIN_EXE_fss-hold");
const EXPORT: &str = env!("CARGO_BIN_EXE_fss-export");
const SOURCE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../fss-container/tests/fixtures/indexed_avc.mp4"
));

// Parallel fixture threads can briefly inherit another thread's deployment lock in a
// forked child until exec closes the descriptor. Only that pre-write refusal is retried.
trait OutputUnlocked {
    fn output_unlocked(&mut self) -> std::io::Result<Output>;
}
impl OutputUnlocked for Command {
    fn output_unlocked(&mut self) -> std::io::Result<Output> {
        for _ in 0..100 {
            let output = self.output()?;
            if output.status.success()
                || !String::from_utf8_lossy(&output.stderr)
                    .contains("reference deployment is locked")
            {
                return Ok(output);
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        self.output()
    }
}

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..128 {
            let path = std::env::temp_dir().join(format!(
                "fss-review-expiry-cli-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("fixture directory capacity exhausted".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn authority(principal: &str) -> Test<ContextAuthority> {
    Ok(ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:review-expiry-cli".into(),
        operation_id: OperationId::parse("operation:review-expiry-cli")?,
        principal: principal.into(),
        capabilities: vec![
            "ADP-REPLAY-001".into(),
            "ADP-FILE-001".into(),
            "adp:file:001".into(),
            "CAP-EXPORT-PREPARE-001".into(),
            "CAP-EXPORT-COMMIT-001".into(),
            "CAP-READ-MEDIA-001".into(),
            "CAP-DELETE-PREPARE-001".into(),
            "CAP-DELETE-COMMIT-001".into(),
        ],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(1024 * 1024 * 1024)
            .storage_operations(131_072)
            .build()?,
        privacy_scope: "privacy:screened-review-media-v1".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?)
}

fn interval(earliest: i128, latest: i128) -> Test<CaptureInterval> {
    Ok(CaptureInterval::new(
        TimestampNs(earliest),
        TimestampNs(latest),
    )?)
}

struct Fixture {
    root: PathBuf,
    source: FileIngestReceipt,
    expired: ReviewMediaRecord,
    current: ReviewMediaRecord,
    _directory: Directory,
}
impl Fixture {
    fn new(label: &str) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let owner = authority(OWNER)?;
        let cx = ReplayCx::from_context_authority(&owner, root.clone())?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let input = directory.0.join("original.mp4");
        fs::write(&input, SOURCE)?;
        let source = FileIngestAdapter::ingest(
            FileIngestRequest::new(
                &input,
                SensorId::parse(SENSOR)?,
                StreamId::parse("stream:review-expiry-cli")?,
            )
            .with_receive_time(TimestampNs(1_000_000_000)),
            &cx,
            &mut deployment,
        )?;
        fs::remove_file(input)?;
        let mut publish = |expires_at| -> Test<ReviewMediaRecord> {
            let request = ReviewMediaRequest {
                movie: ReviewMovieRequest {
                    import_identity: source.import_identity,
                    movie_start_tick: 400,
                    movie_end_tick: 800,
                    limits: ReviewMovieLimits {
                        max_output_bytes: 1024 * 1024,
                        ..ReviewMovieLimits::default()
                    },
                },
                access: ReviewAccessRequest {
                    import_identity: source.import_identity,
                    import_root: source.import_root,
                    sensor: SensorId::parse(SENSOR)?,
                    movie_start_tick: 400,
                    movie_end_tick: 800,
                    expected_privacy: current_mask(&deployment, &SensorId::parse(SENSOR)?)?
                        .digest(),
                    recipient: PrincipalId::parse(READER)?,
                    purpose: "Review one retained fixture interval".into(),
                    issued_at: TimestampNs(10),
                    expires_at: TimestampNs(expires_at),
                    maximum_media_bytes: 1024 * 1024,
                },
            };
            let preview = prepare_review_media(&deployment, &request, &owner, &cx)?;
            let record = preview.record().clone();
            let receipt =
                commit_review_media(&mut deployment, &request, preview.approval(), &owner, &cx)?;
            assert_eq!(receipt.root, record.root());
            Ok(record)
        };
        let expired = publish(100)?;
        let current = publish(200)?;
        assert_ne!(expired.root(), current.root());
        assert_eq!(expired.media_digest(), current.media_digest());
        drop(deployment);
        cx.drain_and_finalize();
        Ok(Self {
            root,
            source,
            expired,
            current,
            _directory: directory,
        })
    }

    fn cleanup(&self, command: &str, now: &str, exact: Option<(&str, &str)>) -> Test<Output> {
        let mut process = Command::new(EVENT);
        process
            .args(["delete", command])
            .arg("--root")
            .arg(&self.root);
        process.args([
            "--site",
            SITE,
            "--sensor-id",
            SENSOR,
            "--attested-now-ns",
            now,
        ]);
        if let Some((plan, approval)) = exact {
            process.args(["--plan", plan, "--approve", approval]);
        }
        Ok(process.output_unlocked()?)
    }

    fn hold(&self, command: &str, approval: Option<&str>) -> Test<Value> {
        let mut process = Command::new(HOLD);
        process.arg(command).arg("--root").arg(&self.root).args([
            "--site",
            SITE,
            "--hold-id",
            "retain-source-review",
            "--import-id",
            &self.source.import_identity.to_text(),
            "--reason",
            "Preserve original evidence and its review derivatives",
        ]);
        if let Some(approval) = approval {
            process.args(["--approve", approval]);
        }
        success(&process.output_unlocked()?)
    }

    fn verify_original_and_current_review(&self) -> Test {
        let reader = authority(READER)?;
        let cx = ReplayCx::from_context_authority(&reader, self.root.clone())?;
        let deployment = ReferenceDeployment::reopen(&self.root, SITE, &cx)?;
        RetainedFileImport::open(
            &deployment,
            self.source.import_identity,
            RetainedReadLimits::default(),
            &cx,
        )?;
        assert!(
            DeletionIndex::read(&deployment)?
                .import(self.source.import_identity)
                .is_none()
        );
        let media = read_review_media(
            &deployment,
            self.current.root(),
            interval(100, 101)?,
            &reader,
            &cx,
        )?;
        assert_eq!(
            ContentDigest::sha256(media.bytes()),
            self.current.media_digest()
        );
        assert!(
            read_review_media(
                &deployment,
                self.expired.root(),
                interval(20, 30)?,
                &reader,
                &cx,
            )
            .is_err(),
            "deleted review became readable with an earlier time assertion"
        );
        drop(deployment);
        cx.drain_and_finalize();
        Ok(())
    }
}

fn field<'a>(value: &'a Value, key: &str) -> Test<&'a Value> {
    value
        .object()
        .and_then(|object| object.get(key))
        .ok_or_else(|| format!("missing JSON field {key}").into())
}
fn text<'a>(value: &'a Value, key: &str) -> Test<&'a str> {
    field(value, key)?
        .text()
        .ok_or_else(|| format!("nontext JSON field {key}").into())
}
fn success(output: &Output) -> Test<Value> {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(json_input::parse(std::str::from_utf8(&output.stdout)?)?)
}
fn refused(output: &Output, expected: &str) {
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "refusal wrote a partial JSON document"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(expected),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn snapshot(root: &Path) -> Test<BTreeMap<PathBuf, ContentDigest>> {
    let mut result = BTreeMap::new();
    let mut pending = vec![root.to_owned()];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            } else {
                result.insert(
                    entry.path().strip_prefix(root)?.to_owned(),
                    ContentDigest::sha256(&fs::read(entry.path())?),
                );
            }
        }
    }
    Ok(result)
}

#[test]
fn expiry_cli_preserves_originals_and_shared_live_media_with_exact_cold_retry() -> Test {
    let f = Fixture::new("shared")?;
    let before = snapshot(&f.root)?;
    let uncertain = success(&f.cleanup("review-expiry-plan", "99:101", None)?)?;
    assert_eq!(text(&uncertain, "status")?, "nothing_eligible");
    let candidates = field(field(&uncertain, "selection")?, "candidates")?
        .array()
        .ok_or("candidate array")?;
    assert!(candidates.iter().any(|candidate| {
        text(candidate, "disposition").is_ok_and(|state| state == "expiry_uncertain")
    }));
    let preview = success(&f.cleanup("review-expiry-plan", "100:100", None)?)?;
    assert_eq!(text(&preview, "status")?, "planned");
    let plan = field(&preview, "deletion_plan")?;
    assert_eq!(
        field(plan, "imports")?
            .array()
            .ok_or("imports array")?
            .len(),
        0
    );
    assert_eq!(text(field(plan, "scope")?, "kind")?, "review_expiry");
    assert!(text(plan, "approve_command")?.contains("review-expiry-commit"));
    let digest = text(plan, "plan_digest")?;
    let approval = text(plan, "approval_digest")?;
    assert_eq!(snapshot(&f.root)?, before, "preview changed durable state");
    let completed =
        success(&f.cleanup("review-expiry-commit", "100:100", Some((digest, approval)))?)?;
    assert_eq!(text(&completed, "outcome")?, "completed");
    f.verify_original_and_current_review()?;
    let shown = success(
        &Command::new(EXPORT)
            .arg("review-show")
            .arg("--root")
            .arg(&f.root)
            .args(["--site", SITE, "--review-root", &f.expired.root().to_text()])
            .output_unlocked()?,
    )?;
    assert_eq!(text(&shown, "status")?, "deleted_review_metadata");
    assert_eq!(text(&shown, "media_access")?, "denied");
    assert_eq!(field(&shown, "deletion_complete")?.boolean(), Some(true));
    assert_eq!(field(&shown, "grant_revoked")?.boolean(), Some(false));
    assert_eq!(text(&shown, "deletion_plan_digest")?, digest);
    let after = snapshot(&f.root)?;
    let retry =
        success(&f.cleanup("review-expiry-commit", "100:100", Some((digest, approval)))?)?;
    assert_eq!(text(&retry, "outcome")?, "already_complete");
    assert_eq!(
        text(&retry, "completion_digest")?,
        text(&completed, "completion_digest")?
    );
    assert_eq!(
        snapshot(&f.root)?,
        after,
        "exact retry changed durable state"
    );
    let remaining = success(&f.cleanup("review-expiry-plan", "100:100", None)?)?;
    assert_eq!(text(&remaining, "status")?, "nothing_eligible");
    Ok(())
}

#[test]
fn hold_added_after_preview_invalidates_expiry_and_preserves_every_source_derivative() -> Test {
    let f = Fixture::new("hold")?;
    let preview = success(&f.cleanup("review-expiry-plan", "100:100", None)?)?;
    let plan = field(&preview, "deletion_plan")?;
    let hold = f.hold("place", None)?;
    f.hold("place", Some(text(field(&hold, "result")?, "approval_digest")?))?;
    let before = snapshot(&f.root)?;
    refused(
        &f.cleanup(
            "review-expiry-commit",
            "100:100",
            Some((text(plan, "plan_digest")?, text(plan, "approval_digest")?)),
        )?,
        "ERR-DELETION-PLAN-STALE-001",
    );
    let blocked = success(&f.cleanup("review-expiry-plan", "100:100", None)?)?;
    assert_eq!(text(&blocked, "status")?, "blocked");
    let candidates = field(field(&blocked, "selection")?, "candidates")?
        .array()
        .ok_or("candidate array")?;
    assert!(candidates.iter().any(|candidate| {
        text(candidate, "disposition").is_ok_and(|state| state == "closure_blocked")
    }));
    assert_eq!(snapshot(&f.root)?, before, "hold refusal mutated custody");
    let release = f.hold("release", None)?;
    f.hold("release", Some(text(field(&release, "result")?, "approval_digest")?))?;
    let renewed = success(&f.cleanup("review-expiry-plan", "100:100", None)?)?;
    let plan = field(&renewed, "deletion_plan")?;
    success(&f.cleanup(
        "review-expiry-commit",
        "100:100",
        Some((text(plan, "plan_digest")?, text(plan, "approval_digest")?)),
    )?)?;
    f.verify_original_and_current_review()?;
    Ok(())
}

#[test]
fn changed_time_and_wrong_approval_cannot_reuse_preview_or_completed_cleanup() -> Test {
    let f = Fixture::new("bindings")?;
    let preview = success(&f.cleanup("review-expiry-plan", "100:100", None)?)?;
    let plan = field(&preview, "deletion_plan")?;
    let digest = text(plan, "plan_digest")?;
    let approval = text(plan, "approval_digest")?;
    let before = snapshot(&f.root)?;
    refused(
        &f.cleanup("review-expiry-commit", "101:101", Some((digest, approval)))?,
        "ERR-DELETION-PLAN-STALE-001",
    );
    refused(
        &f.cleanup(
            "review-expiry-commit",
            "100:100",
            Some((digest, &ContentDigest::sha256(b"wrong approval").to_text())),
        )?,
        "ERR-DELETION-APPROVAL-001",
    );
    assert_eq!(snapshot(&f.root)?, before);
    success(&f.cleanup("review-expiry-commit", "100:100", Some((digest, approval)))?)?;
    let after = snapshot(&f.root)?;
    refused(
        &f.cleanup("review-expiry-commit", "101:101", Some((digest, approval)))?,
        "ERR-DELETION-PLAN-STALE-001",
    );
    assert_eq!(snapshot(&f.root)?, after);
    Ok(())
}

#[test]
fn a_new_approved_review_can_recreate_expired_media_without_reviving_old_grants() -> Test {
    let f = Fixture::new("reissue")?;
    let preview = success(&f.cleanup("review-expiry-plan", "200:200", None)?)?;
    let plan = field(&preview, "deletion_plan")?;
    success(&f.cleanup(
        "review-expiry-commit",
        "200:200",
        Some((text(plan, "plan_digest")?, text(plan, "approval_digest")?)),
    )?)?;
    let owner = authority(OWNER)?;
    let cx = ReplayCx::from_context_authority(&owner, f.root.clone())?;
    let deployment = ReferenceDeployment::reopen(&f.root, SITE, &cx)?;
    assert!(
        !deployment
            .publisher()
            .spool()
            .object_path(f.current.media_digest())
            .exists()
    );
    let mask = current_mask(&deployment, &SensorId::parse(SENSOR)?)?
        .digest()
        .to_text();
    drop(deployment);
    cx.drain_and_finalize();

    let publish = |approval: Option<&str>| -> Test<Value> {
        let mut process = Command::new(EXPORT);
        process.arg("review").arg("--root").arg(&f.root).args([
            "--site",
            SITE,
            "--import-identity",
            &f.source.import_identity.to_text(),
            "--expected-import-root",
            &f.source.import_root.to_text(),
            "--sensor",
            SENSOR,
            "--movie-start-tick",
            "400",
            "--movie-end-tick",
            "800",
            "--privacy-digest",
            &mask,
            "--recipient",
            READER,
            "--purpose",
            "A newly approved review of the preserved original",
            "--issued-at-ns",
            "300",
            "--expires-at-ns",
            "400",
            "--max-media-bytes",
            "1048576",
        ]);
        if let Some(approval) = approval {
            process.args(["--approve", approval]);
        }
        success(&process.output_unlocked()?)
    };
    let before = snapshot(&f.root)?;
    let prepared = publish(None)?;
    assert_eq!(text(&prepared, "status")?, "awaiting_publication_approval");
    assert_eq!(snapshot(&f.root)?, before, "new grant preview wrote media");
    let published = publish(Some(text(&prepared, "approval_digest")?))?;
    let new_root = ContentDigest::parse(text(&published, "review_root")?)?;
    assert_ne!(new_root, f.expired.root());
    assert_ne!(new_root, f.current.root());

    let reader = authority(READER)?;
    let cx = ReplayCx::from_context_authority(&reader, f.root.clone())?;
    let deployment = ReferenceDeployment::reopen(&f.root, SITE, &cx)?;
    let media = read_review_media(&deployment, new_root, interval(300, 301)?, &reader, &cx)?;
    assert_eq!(
        ContentDigest::sha256(media.bytes()),
        f.current.media_digest()
    );
    for root in [f.expired.root(), f.current.root()] {
        assert!(read_review_media(&deployment, root, interval(20, 21)?, &reader, &cx).is_err());
    }
    RetainedFileImport::open(
        &deployment,
        f.source.import_identity,
        RetainedReadLimits::default(),
        &cx,
    )?;
    drop(deployment);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn malformed_expiry_cli_refuses_before_opening_or_creating_a_deployment() -> Test {
    let directory = Directory::new("invalid")?;
    let missing = directory.0.join("must-not-exist");
    for (command, extra) in [
        ("review-expiry-plan", vec!["--sensor-id", SENSOR]),
        (
            "review-expiry-plan",
            vec!["--sensor-id", SENSOR, "--attested-now-ns", "20:10"],
        ),
        (
            "review-expiry-commit",
            vec!["--sensor-id", SENSOR, "--attested-now-ns", "100:100"],
        ),
        (
            "review-expiry-plan",
            vec![
                "--sensor-id",
                SENSOR,
                "--attested-now-ns",
                "100:100",
                "--retain-for-ns",
                "1",
            ],
        ),
    ] {
        let output = Command::new(EVENT)
            .args(["delete", command])
            .arg("--root")
            .arg(&missing)
            .args(["--site", SITE])
            .args(extra)
            .output_unlocked()?;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!missing.exists());
    }
    Ok(())
}
