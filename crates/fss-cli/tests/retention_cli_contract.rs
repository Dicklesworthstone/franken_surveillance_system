#![forbid(unsafe_code)]
//! Owner-requested retention through real file imports, deletion storage and CLI processes.
//! Synthetic JPEG bytes are retained, not a hand-built ledger or mocked selector. These tests
//! assert the actual cohort, surviving bytes, exact approvals and every deletion cut point.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, CaptureInterval, ContentDigest, OperationId, SensorId, TimestampNs};
use fss_reference::deletion::retention::{
    RetentionDisposition, RetentionRequest, assess_retention, commit_retention, plan_retention,
};
use fss_reference::deletion::{
    CommitOutcome, DELETION_CUT_POINTS, DeletionCompletion, DeletionError, DeletionIndex,
    DeletionPlan,
};
use fss_reference::ingest::{RetainedFileImport, RetainedReadLimits};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ReferenceDeployment, ReplayCx};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const SITE: &str = "site:retention-cli";
const SENSOR: &str = "sensor:retention";
const PRINCIPAL: &str = "principal:local-operator";
const KEEP_NS: u64 = 1_000_000_000;
const NOW: i128 = 6_000_000_000;

struct Directory(PathBuf);
impl Directory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-retention-{name}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("test directory capacity".into())
    }
    fn root(&self) -> PathBuf {
        self.0.join("deployment")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// Concurrent test processes can briefly inherit another test's lock descriptor until exec.
// Retry only that exact pre-write refusal, with a fixed ceiling; never retry another error.
fn output(command: &mut Command) -> TestResult<Output> {
    for _ in 0..100 {
        let output = command.output()?;
        if !String::from_utf8_lossy(&output.stderr).contains("reference deployment is locked") {
            return Ok(output);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err("deployment lock remained held".into())
}
fn success(value: &Output) {
    assert!(
        value.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&value.stdout),
        String::from_utf8_lossy(&value.stderr)
    );
}
fn refused(value: &Output, identity: &str) {
    assert!(!value.status.success());
    assert!(value.stdout.is_empty(), "refusal published a report prefix");
    assert!(
        String::from_utf8_lossy(&value.stderr).contains(identity),
        "{}",
        String::from_utf8_lossy(&value.stderr)
    );
}
fn digest_field(value: &Output, key: &str) -> TestResult<ContentDigest> {
    success(value);
    let text = std::str::from_utf8(&value.stdout)?;
    let marker = format!("\"{key}\":\"");
    let rest = text.split_once(&marker).ok_or("missing digest field")?.1;
    let token = rest.split_once('"').ok_or("unterminated digest")?.0;
    Ok(ContentDigest::parse(token)?)
}
fn context(root: &Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:retention-test".into(),
        operation_id: OperationId::parse("operation:retention-test")?,
        principal: PRINCIPAL.to_owned(),
        capabilities: vec![
            "ADP-REPLAY-001".into(),
            "CAP-DELETE-PREPARE-001".into(),
            "CAP-DELETE-COMMIT-001".into(),
        ],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(1 << 20).build()?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    authority.validate()?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}
fn open(root: &Path, cx: &ReplayCx) -> TestResult<ReferenceDeployment> {
    for _ in 0..100 {
        match ReferenceDeployment::open(root, SITE, cx) {
            Err(error) if error.is_deployment_locked() => {
                std::thread::sleep(Duration::from_millis(20))
            }
            other => return Ok(other?),
        }
    }
    Err("deployment lock remained held".into())
}
fn request(now: i128) -> TestResult<RetentionRequest> {
    Ok(RetentionRequest::new(
        SensorId::parse(SENSOR)?,
        KEEP_NS,
        CaptureInterval::new(TimestampNs(now), TimestampNs(now))?,
    )?)
}
fn files(root: &Path) -> TestResult<BTreeMap<PathBuf, ContentDigest>> {
    let mut found = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let kind = fs::symlink_metadata(&path)?.file_type();
        if kind.is_dir() {
            for entry in fs::read_dir(&path)? {
                pending.push(entry?.path());
            }
        } else if kind.is_file() {
            found.insert(
                path.strip_prefix(root)?.to_path_buf(),
                ContentDigest::sha256(&fs::read(path)?),
            );
        }
    }
    Ok(found)
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
fn movie(level: u8) -> TestResult<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let frame = encode_jpeg(32, 32, &vec![level; 1024], &config)?;
    Ok(frame.repeat(4))
}
fn import(
    dir: &Directory,
    name: &str,
    sensor: &str,
    start: Option<i128>,
    bytes: &[u8],
) -> TestResult<ContentDigest> {
    let input = dir.0.join(format!("{name}.mjpeg"));
    fs::write(&input, bytes)?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-file"));
    command
        .args(["import", "--root"])
        .arg(dir.root())
        .args(["--site", SITE, "--input"])
        .arg(input)
        .args([
            "--sensor",
            sensor,
            "--stream",
            &format!("stream:{sensor}"),
            "--media-format",
            "mjpeg",
            "--receive-time-ns",
            "10000000000000",
        ]);
    if let Some(start) = start {
        command.args([
            "--capture-start-ns",
            &start.to_string(),
            "--capture-uncertainty-ns",
            "1000000",
            "--assumed-fps",
            "10",
        ]);
    }
    let value = output(&mut command)?;
    success(&value);
    let text = std::str::from_utf8(&value.stdout)?;
    let id = text
        .lines()
        .find_map(|line| line.strip_prefix("import_identity="))
        .ok_or("missing import identity")?;
    Ok(ContentDigest::parse(id)?)
}
fn cli(
    root: &Path,
    verb: &str,
    now: i128,
    approval: Option<(ContentDigest, ContentDigest)>,
) -> TestResult<Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-event"));
    command.args(["delete", verb, "--root"]).arg(root).args([
        "--site",
        SITE,
        "--sensor-id",
        SENSOR,
        "--retain-for-ns",
        &KEEP_NS.to_string(),
        "--attested-now-ns",
        &format!("{now}:{now}"),
    ]);
    if let Some((plan, approval)) = approval {
        command.args(["--plan", &plan.to_text(), "--approve", &approval.to_text()]);
    }
    output(&mut command)
}
fn plan(root: &Path, now: i128) -> TestResult<DeletionPlan> {
    let cx = context(root)?;
    let deployment = open(root, &cx)?;
    Ok(plan_retention(&deployment, &request(now)?, &cx)?
        .deletion
        .ok_or("no eligible plan")?)
}
fn hold(
    root: &Path,
    verb: &str,
    identity: ContentDigest,
    approval: Option<ContentDigest>,
) -> TestResult<Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-hold"));
    command.arg(verb).arg("--root").arg(root).args([
        "--site",
        SITE,
        "--hold-id",
        "incident",
        "--import-id",
        &identity.to_text(),
        "--reason",
        "Owner incident review",
    ]);
    if let Some(approval) = approval {
        command.args(["--approve", &approval.to_text()]);
    }
    output(&mut command)
}

#[test]
fn exact_old_cohort_deletes_derivatives_but_preserves_recent_unknown_and_shared_source()
-> TestResult {
    let dir = Directory::new("cohort")?;
    let shared = movie(40)?;
    let first = import(&dir, "first", SENSOR, Some(1_000_000_000), &shared)?;
    let second = import(&dir, "second", SENSOR, Some(2_000_000_000), &movie(60)?)?;
    let recent = import(&dir, "recent", SENSOR, Some(9_000_000_000), &movie(80)?)?;
    let unknown = import(&dir, "unknown", SENSOR, None, &movie(100)?)?;
    let outside = import(
        &dir,
        "outside",
        "sensor:other",
        Some(1_000_000_000),
        &shared,
    )?;
    let root = dir.root();
    let decoded = output(
        Command::new(env!("CARGO_BIN_EXE_fss-file"))
            .args(["decode", "--root"])
            .arg(&root)
            .args([
                "--site",
                SITE,
                "--import-id",
                &first.to_text(),
                "--segment",
                "1",
                "--interpretation",
                "gray",
            ]),
    )?;
    success(&decoded);
    let planned = plan(&root, NOW)?;
    assert_eq!(
        planned.imports.iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([first, second])
    );
    assert!(
        planned
            .units
            .iter()
            .any(|unit| unit.kind == "decoded_frames")
    );
    assert!(planned.blockers.is_empty(), "{:?}", planned.blockers);
    assert!(
        planned
            .retained
            .iter()
            .any(|o| o.reason == "shared_with_retained_authority")
    );
    let bytes = planned.canonical_bytes()?;
    assert_eq!(DeletionPlan::decode(&bytes, planned.digest()?)?, planned);
    assert_eq!(planned.domain(), "fss.deletion_plan.v3");
    let cx = context(&root)?;
    let retained_bytes = {
        let deployment = open(&root, &cx)?;
        let assessment = assess_retention(&deployment, &request(NOW)?, &cx)?;
        let decisions: BTreeMap<_, _> = assessment
            .selection
            .candidates()
            .iter()
            .map(|c| (c.import_identity(), c.disposition()))
            .collect();
        assert_eq!(
            decisions,
            BTreeMap::from([
                (first, RetentionDisposition::Eligible),
                (second, RetentionDisposition::Eligible),
                (recent, RetentionDisposition::NotDue),
                (unknown, RetentionDisposition::CaptureTimeUnknown),
            ])
        );
        assert_eq!(assessment.outside_sensor, 1);
        planned
            .retained
            .iter()
            .map(|o| Ok((o.digest, deployment.publisher().spool().read(o.digest)?)))
            .collect::<TestResult<BTreeMap<_, _>>>()?
    };
    let before = files(&root)?;
    let preview = cli(&root, "retention-plan", NOW, None)?;
    success(&preview);
    assert_eq!(digest_field(&preview, "plan_digest")?, planned.digest()?);
    let approval = digest_field(&preview, "approval_digest")?;
    assert_eq!(approval, planned.approval_digest(PRINCIPAL)?);
    let json = std::str::from_utf8(&preview.stdout)?;
    assert!(json.contains("retention-commit"));
    assert!(json.contains("--retain-for-ns 1000000000 --attested-now-ns 6000000000:6000000000"));
    assert!(json.contains("\"standing_policy_changed\":false"));
    assert_eq!(before, files(&root)?, "preview writes no deployment bytes");
    refused(
        &cli(
            &root,
            "retention-commit",
            NOW,
            Some((planned.digest()?, ContentDigest::sha256(b"wrong"))),
        )?,
        "ERR-DELETION-APPROVAL-001",
    );
    refused(
        &cli(
            &root,
            "retention-commit",
            NOW + 1,
            Some((planned.digest()?, approval)),
        )?,
        "ERR-DELETION-PLAN-STALE-001",
    );
    assert_eq!(
        before,
        files(&root)?,
        "bad approvals and changed time write nothing"
    );
    let committed = cli(
        &root,
        "retention-commit",
        NOW,
        Some((planned.digest()?, approval)),
    )?;
    success(&committed);
    assert!(std::str::from_utf8(&committed.stdout)?.contains("\"outcome\":\"completed\""));
    {
        let deployment = open(&root, &cx)?;
        let index = DeletionIndex::read(&deployment)?;
        assert_eq!(
            index.entries().len(),
            1,
            "one cohort, not one deletion per import"
        );
        let entry = index.plan(planned.digest()?).ok_or("missing deletion")?;
        assert!(entry.is_complete());
        assert_eq!(entry.plan, planned);
        for object in &planned.deletable {
            assert!(
                deployment
                    .publisher()
                    .spool()
                    .state(object.digest)
                    .is_none()
            );
            assert!(!deployment.publisher().object_name_present(object.digest));
        }
        for (digest, bytes) in retained_bytes {
            assert_eq!(deployment.publisher().spool().read(digest)?, bytes);
        }
        for id in [recent, unknown, outside] {
            RetainedFileImport::open(&deployment, id, RetainedReadLimits::default(), &cx)?;
            assert!(index.import(id).is_none());
        }
        for id in [first, second] {
            assert!(index.import(id).is_some());
        }
    }
    assert_eq!(
        fs::read(dir.0.join("first.mjpeg"))?,
        shared,
        "operator input is outside deletion"
    );
    let after = files(&root)?;
    let repeated = cli(
        &root,
        "retention-commit",
        NOW,
        Some((planned.digest()?, approval)),
    )?;
    success(&repeated);
    assert!(std::str::from_utf8(&repeated.stdout)?.contains("\"outcome\":\"already_complete\""));
    assert_eq!(after, files(&root)?);
    Ok(())
}

#[test]
fn member_hold_blocks_every_cohort_member_and_invalidates_old_approval() -> TestResult {
    let dir = Directory::new("held")?;
    let first = import(&dir, "a", SENSOR, Some(1_000_000_000), &movie(40)?)?;
    let second = import(&dir, "b", SENSOR, Some(2_000_000_000), &movie(60)?)?;
    let root = dir.root();
    let original = plan(&root, NOW)?;
    let preview = hold(&root, "place", second, None)?;
    let approval = digest_field(&preview, "approval_digest")?;
    success(&hold(&root, "place", second, Some(approval))?);
    let before = files(&root)?;
    refused(
        &cli(
            &root,
            "retention-commit",
            NOW,
            Some((original.digest()?, original.approval_digest(PRINCIPAL)?)),
        )?,
        "ERR-DELETION-PLAN-STALE-001",
    );
    let blocked = plan(&root, NOW)?;
    assert_eq!(
        blocked.imports.iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([first, second])
    );
    assert!(
        blocked
            .blockers
            .iter()
            .any(|b| b.kind == "evidence_hold" && b.subject == "incident")
    );
    let rendered = cli(&root, "retention-plan", NOW, None)?;
    success(&rendered);
    assert!(std::str::from_utf8(&rendered.stdout)?.contains("\"approve_command\":null"));
    refused(
        &cli(
            &root,
            "retention-commit",
            NOW,
            Some((blocked.digest()?, blocked.approval_digest(PRINCIPAL)?)),
        )?,
        "ERR-DELETION-BLOCKED-001",
    );
    assert_eq!(
        files(&root)?,
        before,
        "no member is deleted and no hold is expired"
    );
    let release = hold(&root, "release", second, None)?;
    success(&hold(
        &root,
        "release",
        second,
        Some(digest_field(&release, "approval_digest")?),
    )?);
    let current = plan(&root, NOW)?;
    assert!(current.blockers.is_empty());
    success(&cli(
        &root,
        "retention-commit",
        NOW,
        Some((current.digest()?, current.approval_digest(PRINCIPAL)?)),
    )?);
    Ok(())
}

#[test]
fn every_deletion_cut_resumes_exact_cohort_without_original_input_files() -> TestResult {
    let dir = Directory::new("cuts")?;
    let first = import(&dir, "a", SENSOR, Some(1_000_000_000), &movie(40)?)?;
    let second = import(&dir, "b", SENSOR, Some(2_000_000_000), &movie(60)?)?;
    let baseline = plan(&dir.root(), NOW)?;
    let digest = baseline.digest()?;
    let approval = baseline.approval_digest(PRINCIPAL)?;
    fs::remove_file(dir.0.join("a.mjpeg"))?;
    fs::remove_file(dir.0.join("b.mjpeg"))?;
    for (position, stage) in DELETION_CUT_POINTS.iter().enumerate() {
        let root = dir.0.join(format!("cut-{position}"));
        copy_tree(&dir.root(), &root)?;
        let had_record = {
            let cx = context(&root)?;
            cx.set_cancel_at_checkpoint(stage);
            let mut deployment = open(&root, &cx)?;
            let result = commit_retention(
                &mut deployment,
                &request(NOW)?,
                digest,
                approval,
                PRINCIPAL,
                &cx,
            );
            assert!(
                matches!(result, Err(DeletionError::Cancelled { stage: actual }) if actual == *stage),
                "{stage}: {result:?}"
            );
            let index = DeletionIndex::read(&deployment)?;
            let recorded = index.plan(digest).is_some();
            assert_eq!(index.import(first).is_some(), recorded);
            assert_eq!(index.import(second).is_some(), recorded);
            recorded
        };
        let cx = context(&root)?;
        {
            let mut deployment = open(&root, &cx)?;
            let receipt = commit_retention(
                &mut deployment,
                &request(NOW)?,
                digest,
                approval,
                PRINCIPAL,
                &cx,
            )?;
            assert_eq!(
                receipt.outcome,
                if had_record {
                    CommitOutcome::Resumed
                } else {
                    CommitOutcome::Completed
                }
            );
            assert_eq!(receipt.plan, baseline);
            assert_eq!(receipt.completion, DeletionCompletion::of(&baseline)?);
            assert_eq!(receipt.completion.domain(), "fss.deletion_completion.v3");
            let bytes = receipt.completion.canonical_bytes()?;
            assert_eq!(
                DeletionCompletion::decode(&bytes, receipt.completion_digest)?,
                receipt.completion
            );
            assert_eq!(DeletionIndex::read(&deployment)?.entries().len(), 1);
        }
        let before_retry = files(&root)?;
        {
            let mut deployment = open(&root, &cx)?;
            assert!(matches!(
                commit_retention(
                    &mut deployment,
                    &request(NOW + 1)?,
                    digest,
                    approval,
                    PRINCIPAL,
                    &cx
                ),
                Err(DeletionError::StalePlan(_))
            ));
            let receipt = commit_retention(
                &mut deployment,
                &request(NOW)?,
                digest,
                approval,
                PRINCIPAL,
                &cx,
            )?;
            assert_eq!(receipt.outcome, CommitOutcome::AlreadyComplete);
        }
        assert_eq!(
            before_retry,
            files(&root)?,
            "retry at {stage} duplicated authority"
        );
    }
    Ok(())
}

#[test]
fn later_import_invalidates_plan_and_v3_cannot_be_relabelled_or_have_members_dropped() -> TestResult
{
    let dir = Directory::new("stale")?;
    import(&dir, "a", SENSOR, Some(1_000_000_000), &movie(40)?)?;
    let original = plan(&dir.root(), NOW)?;
    let bytes = original.canonical_bytes()?;
    let domain = b"fss.deletion_plan.v3";
    let at = bytes
        .windows(domain.len())
        .position(|part| part == domain)
        .ok_or("no v3 domain")?;
    let mut relabelled = bytes.clone();
    relabelled[at + domain.len() - 1] = b'2';
    assert!(DeletionPlan::decode(&relabelled, ContentDigest::sha256(&relabelled)).is_err());
    let mut dropped = original.clone();
    dropped.imports.clear();
    assert!(dropped.canonical_bytes().is_err());
    import(&dir, "b", SENSOR, Some(2_000_000_000), &movie(60)?)?;
    let before = files(&dir.root())?;
    refused(
        &cli(
            &dir.root(),
            "retention-commit",
            NOW,
            Some((original.digest()?, original.approval_digest(PRINCIPAL)?)),
        )?,
        "ERR-DELETION-PLAN-STALE-001",
    );
    assert_eq!(before, files(&dir.root())?);
    assert_eq!(plan(&dir.root(), NOW)?.imports.len(), 2);
    Ok(())
}

#[test]
fn unknown_and_recent_recordings_return_explicit_noop_without_an_approval() -> TestResult {
    let dir = Directory::new("empty")?;
    import(&dir, "recent", SENSOR, Some(9_000_000_000), &movie(60)?)?;
    import(&dir, "unknown", SENSOR, None, &movie(40)?)?;
    let before = files(&dir.root())?;
    let preview = cli(&dir.root(), "retention-plan", NOW, None)?;
    success(&preview);
    let text = std::str::from_utf8(&preview.stdout)?;
    assert!(text.contains("\"status\":\"nothing_eligible\""));
    assert!(text.contains("\"deletion_plan\":null"));
    assert!(text.contains("capture_time_unknown"));
    assert!(!text.contains("approval_digest"));
    assert_eq!(before, files(&dir.root())?);
    Ok(())
}
