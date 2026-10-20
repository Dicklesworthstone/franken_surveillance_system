#![forbid(unsafe_code)]
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
//! Cold process inspection of real journaled multipart ownership, with no provider adapter.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use fss_cli::json_input::{Value, parse};
use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec,
    RuntimeGrant, TimestampNs,
};
use fss_object::multipart::{
    MultipartTransport, PartReceipt, Reconciliation, TransportCx, UploadId, UploadIntent,
    UploadJournalPin,
};
use fss_object::planner::{ChunkPolicy, MIN_PART_SIZE, PlannedChunk};
use fss_object::upload_journal::{FileUploadJournal, UploadJournalLimits};
use fss_object::uploader::{StagedUpload, minimum_upload_budget};
use fss_object::{HostSpoolIo, SPOOL_OBJECTS_DIR};
use fss_runtime::authority::AuthorityCx;
use fss_runtime::grant::GrantSet;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const RESOURCE: &str = "archive:owner-test/evidence";
const FOLLOW_UP_NOTE: &str = "private local recovery note excluded from inspection";
const PROVIDER_TOKEN: &str = "private-provider-upload-token-not-a-capability";
const MAX_BYTES: u64 = 1024 * 1024;
const MAX_RECORDS: u64 = 64;

#[derive(Clone)]
struct Options {
    path: PathBuf,
    resource: String,
    limits: UploadJournalLimits,
    minimum: UploadJournalPin,
}

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-upload-journal-cli-{label}-{}-{attempt}",
                std::process::id(),
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                    return Ok(Self(path));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("test directory capacity".into())
    }
    fn journal(&self) -> Options {
        Options {
            path: self.0.join("journal"),
            resource: RESOURCE.into(),
            limits: UploadJournalLimits {
                max_total_bytes: MAX_BYTES,
                max_records: MAX_RECORDS as usize,
                max_checkpoint_bytes: 16 * 1024,
                max_read_bytes: 4 * 1024 * 1024,
            },
            minimum: UploadJournalPin {
                sequence: 1,
                root: ContentDigest::sha256(b"unprepared-test-pin"),
            },
        }
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Bounded injected test transport: initiation succeeds, a dispatched part loses its ACK.
/// No network, subprocess, or test-only production bypass exists.
struct LostPartAck;
impl MultipartTransport for LostPartAck {
    fn initiate(&mut self, cx: &mut TransportCx<'_>, _: &UploadIntent) -> Result<UploadId, String> {
        cx.charge_io(cx.now(), 7, 7)
            .map_err(|error| error.to_string())?;
        Ok(UploadId(PROVIDER_TOKEN.into()))
    }
    fn upload_part(
        &mut self,
        cx: &mut TransportCx<'_>,
        _: &UploadId,
        _: &PlannedChunk,
        _: &[u8],
        _: ContentDigest,
    ) -> Result<PartReceipt, String> {
        cx.charge_io(cx.now(), 9, 9)
            .map_err(|error| error.to_string())?;
        Err("private provider failure body".into())
    }
    fn complete(
        &mut self,
        _: &mut TransportCx<'_>,
        _: &UploadId,
        _: &UploadIntent,
        _: &[PartReceipt],
    ) -> Result<(), String> {
        Err("unexpected complete".into())
    }
    fn abort(
        &mut self,
        _: &mut TransportCx<'_>,
        _: &UploadId,
        _: &UploadIntent,
    ) -> Result<(), String> {
        Err("unexpected abort".into())
    }
    fn reconcile(
        &mut self,
        _: &mut TransportCx<'_>,
        _: &UploadIntent,
    ) -> Result<Reconciliation, String> {
        Err("unexpected reconciliation".into())
    }
}

fn spec(operation: &str, budgets: BudgetVector) -> Test<RootAuthoritySpec> {
    Ok(RootAuthoritySpec {
        trace_id: "trace:upload-journal-cli".into(),
        operation_id: OperationId::parse(operation)?,
        principal: "principal:original-uploader".into(),
        capabilities: [
            RuntimeGrant::ObjectStage,
            RuntimeGrant::ObjectPublish,
            RuntimeGrant::AdapterNet,
        ]
        .into_iter()
        .map(|grant| grant.as_str().to_owned())
        .collect(),
        deadline: None,
        priority: 10,
        budgets,
        privacy_scope: "privacy:upload-owner".into(),
        retention_scope: "retention:upload-owner".into(),
        anchor_universe: ContentDigest::sha256(b"upload-journal-cli"),
        generation: 7,
    })
}

#[derive(Clone, Copy)]
enum SeedState {
    Prepared,
    Uncertain,
    Indeterminate,
    Cancelled,
    Expired,
}

fn seed(options: &mut Options, state: SeedState) -> Test<(ContentDigest, BudgetVector)> {
    let policy = ChunkPolicy {
        part_size: MIN_PART_SIZE,
    };
    let mut allowance = minimum_upload_budget(3, policy)?;
    allowance.bytes += 4096;
    allowance.network_bytes += 4096;
    allowance.storage_operations += 64;
    let mut parent_budget = BudgetVector::ZERO;
    parent_budget.bytes = 64 * 1024 * 1024;
    parent_budget.network_bytes = 8 * 1024 * 1024;
    parent_budget.storage_operations = 20_000;
    let (mut root, mut tree) = AuthorityCx::root(
        spec("operation:process", parent_budget)?,
        RegionId::new("region:process")?,
        RegionKind::Process,
        parent_budget,
        TimestampNs(0),
    )?;
    let grants = [
        RuntimeGrant::ObjectStage,
        RuntimeGrant::ObjectPublish,
        RuntimeGrant::AdapterNet,
    ]
    .into_iter()
    .fold(GrantSet::empty(), |grants, grant| {
        grants.with_scope(grant, [RESOURCE.to_owned()].into_iter().collect())
    });
    root.narrow_grants(grants)?;
    let mut parent = root.scope_down(
        &mut tree,
        RegionId::new("region:property")?,
        RegionKind::Property,
        parent_budget,
        spec("operation:property", parent_budget)?,
        TimestampNs(0),
    )?;
    let mut transport = LostPartAck;
    let mut journal =
        FileUploadJournal::create(&options.path, options.limits, Arc::new(HostSpoolIo))?;
    let mut child_spec = spec("operation:durable-upload", allowance)?;
    if matches!(state, SeedState::Expired) {
        child_spec.deadline = Some(TimestampNs(5));
    }
    let mut upload = StagedUpload::stage(
        &mut parent,
        &mut tree,
        &mut transport,
        OperationId::parse("operation:durable-upload")?,
        3,
        policy,
        ContentDigest::sha256(b"original-manifest-root"),
        child_spec,
        RESOURCE,
        TimestampNs(1),
    )?;
    options.minimum = upload.attach_journal(&tree, TimestampNs(1), &mut journal)?;
    let intent = upload.intent().digest();
    if matches!(state, SeedState::Uncertain | SeedState::Indeterminate) {
        upload.start(&tree, TimestampNs(2))?;
        assert!(
            upload
                .upload_part(&tree, TimestampNs(3), 0, b"abc")
                .is_err()
        );
    }
    if matches!(state, SeedState::Indeterminate) {
        upload.settle_indeterminate(
            &mut tree,
            TimestampNs(4),
            FOLLOW_UP_NOTE,
            ContentDigest::sha256(b"independent-upload-follow-up"),
        )?;
    }
    if matches!(state, SeedState::Cancelled) {
        upload.request_cancellation(&mut tree, TimestampNs(2))?;
    }
    // Dropping the real owner simulates process loss: the journal, not a serialized test snapshot,
    // is all the subsequent fss-archive process can inspect.
    drop(upload);
    Ok((intent, allowance))
}

fn args(options: &Options) -> Vec<OsString> {
    vec![
        "upload-inspect".into(),
        "--journal".into(),
        options.path.as_os_str().into(),
        "--journal-resource".into(),
        options.resource.clone().into(),
        "--minimum-sequence".into(),
        options.minimum.sequence.to_string().into(),
        "--minimum-root".into(),
        options.minimum.root.to_text().into(),
        "--attested-now-ns".into(),
        "10".into(),
        "--max-journal-bytes".into(),
        options.limits.max_total_bytes.to_string().into(),
        "--max-records".into(),
        options.limits.max_records.to_string().into(),
        "--max-checkpoint-bytes".into(),
        options.limits.max_checkpoint_bytes.to_string().into(),
        "--max-read-bytes".into(),
        options.limits.max_read_bytes.to_string().into(),
    ]
}

fn snapshot(root: &Path) -> Test<BTreeMap<PathBuf, Vec<u8>>> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = BTreeMap::new();
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let metadata = entry.file_type()?;
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                files.insert(
                    entry.path().strip_prefix(root)?.to_path_buf(),
                    fs::read(entry.path())?,
                );
            } else {
                return Err("foreign test journal entry".into());
            }
        }
        if files.len() > 256 || pending.len() > 8 {
            return Err("fixture snapshot bound".into());
        }
    }
    Ok(files)
}

fn copy_journal(source: &Path, destination: &Path) -> Test {
    fs::create_dir(destination)?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700))?;
    for (relative, bytes) in snapshot(source)? {
        let target = destination.join(relative);
        fs::create_dir_all(target.parent().ok_or("missing parent")?)?;
        fs::write(target, bytes)?;
    }
    // Preserve empty spool subdirectories too; physical binding, not incomplete layout, must refuse.
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            fs::create_dir_all(destination.join(entry.file_name()))?;
        }
    }
    Ok(())
}

fn run(args: &[OsString]) -> Test<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-archive"))
        .args(args)
        .output()?)
}
fn field<'a>(value: &'a Value, key: &str) -> Test<&'a Value> {
    value
        .object()
        .and_then(|fields| fields.get(key))
        .ok_or_else(|| format!("missing {key}").into())
}
fn text<'a>(value: &'a Value, key: &str) -> Test<&'a str> {
    field(value, key)?
        .text()
        .ok_or_else(|| format!("nontext {key}").into())
}
fn integer(value: &Value, key: &str) -> Test<i128> {
    field(value, key)?
        .integer()
        .ok_or_else(|| format!("noninteger {key}").into())
}
fn success(output: &Output) -> Test<Value> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert!(output.stdout.len() <= 16 * 1024);
    Ok(parse(std::str::from_utf8(&output.stdout)?)?)
}

#[test]
fn cold_inspection_preserves_prepared_journal_and_checks_an_independent_head() -> Test {
    let dir = Directory::new("prepared")?;
    let mut options = dir.journal();
    let (intent, _) = seed(&mut options, SeedState::Prepared)?;
    let original = snapshot(&options.path)?;
    let first = success(&run(&args(&options))?)?;
    assert_eq!(text(&first, "schema")?, "fss.upload_journal_inspection.v1");
    assert_eq!(text(&first, "intent_digest")?, intent.to_text());
    assert_eq!(text(&first, "phase")?, "prepared");
    assert_eq!(integer(&first, "total_parts")?, 1);
    assert_eq!(integer(&first, "confirmed_parts")?, 0);
    assert_eq!(field(&first, "provider_contacted")?.boolean(), Some(false));
    assert_eq!(
        field(&first, "independent_retrievability_verified")?.boolean(),
        Some(false)
    );
    let read_bytes = integer(field(&first, "inspection_work")?, "bytes")?;
    assert!(read_bytes >= original.values().map(Vec::len).sum::<usize>() as i128);
    assert!(read_bytes <= i128::from(options.limits.max_read_bytes));
    assert_eq!(
        field(&first, "namespace_binding_verified")?.boolean(),
        Some(true)
    );
    assert_eq!(field(&first, "legacy_read_only")?.boolean(), Some(false));
    assert_eq!(field(&first, "cancelled")?.boolean(), Some(false));
    assert_eq!(field(&first, "deadline_expired")?.boolean(), Some(false));
    assert!(ContentDigest::parse(text(&first, "namespace_binding")?).is_ok());
    let mut pinned = args(&options);
    pinned.extend([
        "--expected-head".into(),
        text(&first, "journal_head")?.into(),
    ]);
    let second = success(&run(&pinned)?)?;
    assert_eq!(
        field(&second, "expected_head_verified")?.boolean(),
        Some(true)
    );
    assert_eq!(
        field(&first, "upload_consumed")?,
        field(&second, "upload_consumed")?
    );
    assert_eq!(snapshot(&options.path)?, original);
    Ok(())
}

#[test]
fn uncertain_upload_keeps_spent_network_allowance_and_hides_provider_tokens() -> Test {
    let dir = Directory::new("uncertain")?;
    let mut options = dir.journal();
    let (_, allowance) = seed(&mut options, SeedState::Uncertain)?;
    let original = snapshot(&options.path)?;
    let output = run(&args(&options))?;
    let report = success(&output)?;
    assert_eq!(text(&report, "phase")?, "uncertain");
    assert_eq!(text(&report, "uncertain_operation")?, "upload_part");
    assert_eq!(
        text(&report, "next_action")?,
        "reconcile the exact outstanding dispatch before any new provider effect"
    );
    assert_eq!(integer(&report, "confirmed_parts")?, 0);
    let consumed = integer(field(&report, "upload_consumed")?, "networkBytes")?;
    let remaining = integer(field(&report, "upload_remaining")?, "networkBytes")?;
    assert_eq!(consumed, 3 + 7 + 9);
    assert_eq!(consumed + remaining, i128::from(allowance.network_bytes));
    let rendered = std::str::from_utf8(&output.stdout)?;
    assert!(!rendered.contains(PROVIDER_TOKEN));
    assert!(!rendered.contains("private provider failure body"));
    assert_eq!(snapshot(&options.path)?, original);
    Ok(())
}

#[test]
fn wrong_heads_bounds_paths_and_corrupt_history_fail_without_mutation() -> Test {
    let dir = Directory::new("refusals")?;
    let mut options = dir.journal();
    seed(&mut options, SeedState::Uncertain)?;
    let original = snapshot(&options.path)?;
    let mut wrong_head = args(&options);
    wrong_head.extend([
        "--expected-head".into(),
        ContentDigest::sha256(b"different-head").to_text().into(),
    ]);
    let mut tiny = options.clone();
    tiny.limits.max_total_bytes = 1;
    let mut wrong_minimum = options.clone();
    wrong_minimum.minimum.root = ContentDigest::sha256(b"unrelated-minimum-pin");
    let mut wrong_resource = options.clone();
    wrong_resource.resource = "archive:other".into();
    let mut missing = options.clone();
    missing.path = dir.0.join("missing.journal");
    let mut copied = options.clone();
    copied.path = dir.0.join("copied.journal");
    copy_journal(&options.path, &copied.path)?;
    for arguments in [
        wrong_head,
        args(&tiny),
        args(&wrong_minimum),
        args(&wrong_resource),
        args(&missing),
        args(&copied),
    ] {
        let output = run(&arguments)?;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(snapshot(&options.path)?, original);
    }
    assert!(!missing.path.exists());
    let object = fs::read_dir(options.path.join(SPOOL_OBJECTS_DIR))?
        .next()
        .ok_or("missing committed object")??
        .path();
    let mut damaged = fs::read(&object)?;
    damaged[0] ^= 1;
    fs::write(&object, &damaged)?;
    let corrupted = snapshot(&options.path)?;
    let output = run(&args(&options))?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(snapshot(&options.path)?, corrupted);
    Ok(())
}

#[test]
fn indeterminate_settlement_exposes_follow_up_reference_without_private_note() -> Test {
    let dir = Directory::new("indeterminate")?;
    let mut options = dir.journal();
    seed(&mut options, SeedState::Indeterminate)?;
    let original = snapshot(&options.path)?;
    let output = run(&args(&options))?;
    let report = success(&output)?;
    assert_eq!(field(&report, "locally_settled")?.boolean(), Some(true));
    assert_eq!(text(&report, "phase")?, "uncertain");
    assert_eq!(
        text(&report, "reconciliation_reference")?,
        ContentDigest::sha256(b"independent-upload-follow-up").to_text()
    );
    assert_eq!(
        text(&report, "next_action")?,
        "retain the durable indeterminate reference for separately authorized reconciliation"
    );
    assert!(!std::str::from_utf8(&output.stdout)?.contains(FOLLOW_UP_NOTE));
    assert!(!std::str::from_utf8(&output.stdout)?.contains(PROVIDER_TOKEN));
    assert_eq!(snapshot(&options.path)?, original);
    Ok(())
}

#[test]
fn cancelled_and_expired_journals_allow_only_cleanup_in_the_report() -> Test {
    for (label, state, cancelled, expired) in [
        ("cancelled", SeedState::Cancelled, true, false),
        ("expired", SeedState::Expired, false, true),
    ] {
        let dir = Directory::new(label)?;
        let mut options = dir.journal();
        seed(&mut options, state)?;
        let original = snapshot(&options.path)?;
        let report = success(&run(&args(&options))?)?;
        assert_eq!(text(&report, "phase")?, "prepared");
        assert_eq!(field(&report, "cancelled")?.boolean(), Some(cancelled));
        assert_eq!(field(&report, "deadline_expired")?.boolean(), Some(expired));
        if expired {
            assert_eq!(text(&report, "deadline_ns")?, "5");
        }
        assert_eq!(
            text(&report, "next_action")?,
            "recover only for bounded cancellation or abort settlement; new payload work is refused"
        );
        assert_eq!(
            integer(field(&report, "upload_consumed")?, "networkBytes")?,
            0
        );
        assert_eq!(snapshot(&options.path)?, original);
    }
    Ok(())
}
