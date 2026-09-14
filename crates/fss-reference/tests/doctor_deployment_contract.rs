#![forbid(unsafe_code)]
//! Contract tests for the read-only deployment doctor (fss-2h5zq.57, CAP- DOCTOR).
//!
//! Every fault root is built with `ReferenceDeployment` (or the owning crate's writer), and every
//! assertion compares exact JSON: either the whole report or the whole check. Each inspection is
//! bracketed by a tree digest (path, mode, size, mtime, ctime, inode, link count, listing, and
//! content of every file up to 1 MiB) that must be unchanged. A second proof runs the doctor
//! through a `RecordingSpoolIo`, a recording journal reader, and a spying lock table. It asserts
//! zero mutating or locking I/O calls, bounded reads only, and that no lock owned by this process
//! was ever held on the deployment's lock files while the doctor observed the lock table.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use fss_core::{
    BatchId, BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, EffectIntent,
    EffectState, EvidenceDelta, IdempotencyKey, ObjectId, ObligationId, OperationId, Plane,
    RootAuthoritySpec, TimestampNs,
};
use fss_ledger::{
    DurableLedgerLimits, DurableReferenceLedger, HostJournalReadIo, IncompleteTailPolicy,
    JournalFileMetadata, JournalReadIo,
};
use fss_object::{HostSpoolIo, ObjectManifest, RecordingSpoolIo, SPOOL_LOCK_FILE, SpoolLimits};
use fss_publication::{
    HostLockTableSource, LOCAL_LOCK_FILE, LOCAL_ROOTS_DIR, LOCAL_SPOOL_DIR, LocalPublicationLimits,
    LocalRootPublisher, LockTableSource, ROOT_RECORD_SUFFIX, ROOT_TEMP_SUFFIX, SlotName,
    StringLockTableSource, decode_st_dev,
};
use fss_reference::doctor::{
    DoctorIo, DoctorLimits, DoctorReport, DoctorVerdict, inspect_deployment,
    inspect_deployment_with,
};
use fss_reference::reference_deployment::{
    DeploymentLimits, FAMILY_FILE_IMPORT_MANIFEST, RELATIVE_PATH_EFFECTS, RELATIVE_PATH_LEDGER,
    RELATIVE_PATH_OBJECTS,
};
use fss_reference::{
    ADP_REPLAY_ROW_ID, DurableEffectJournal, ReferenceDeployment, ReplayCx, ReplayIoAuthority,
};

type TestResult = Result<(), Box<dyn Error>>;
type Res<T> = Result<T, Box<dyn Error>>;

const LINEAGE: &str = "site:doctor-contract";
const TRACKING: &str = "fss-2h5zq.15";
const DEFAULT_LIMITS_JSON: &str = "{\"max_journal_bytes\":67108864,\"max_layout_bytes\":4096,\"max_listed_ids\":32,\"max_sidecar_entries\":4096}";
const OVER_BUDGET_DETAIL: &str = "the file exceeds the doctor's read bound; it was not read and no claim is made about its contents";
const CONTENT_DIGEST_MAX: u64 = 1024 * 1024;

// ---------------------------------------------------------------- fixtures

fn fresh(name: &str) -> Res<PathBuf> {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("doctor_deployment_contract")
        .join(name);
    match fs::remove_dir_all(&base) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    fs::create_dir_all(&base)?;
    Ok(base)
}

fn test_cx(label: &str) -> Res<ReplayCx> {
    let spec = RootAuthoritySpec {
        trace_id: format!("trace:doctor-{label}"),
        operation_id: OperationId::parse(format!("operation:doctor-{label}"))?,
        principal: format!("operator:doctor-{label}"),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_string()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".to_string(),
        retention_scope: "retention:ephemeral".to_string(),
        anchor_universe: ContentDigest::sha256(b"doctor-anchor-universe"),
        generation: 1,
    };
    let root_auth = ContextAuthority::new_root(spec)?;
    let scratch = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("doctor_deployment_contract_cx")
        .join(label);
    let io = ReplayIoAuthority::from_context_authority(&root_auth, scratch)?;
    Ok(ReplayCx::new(io))
}

/// A closed, freshly initialized `ReferenceDeployment` root.
fn init(name: &str) -> Res<PathBuf> {
    let base = fresh(name)?;
    let deployment = ReferenceDeployment::open(&base, LINEAGE, &test_cx(name)?)?;
    drop(deployment);
    Ok(base)
}

fn small_limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(8, 16, 8, 64, SpoolLimits::new(64, 1 << 20, 4096, 64))
}

fn publish(dep: &Path, slot: &str) -> TestResult {
    let mut local = LocalRootPublisher::open(dep.join(RELATIVE_PATH_OBJECTS), small_limits())?;
    let child = local.stage_object(format!("clip-{slot}").as_bytes())?;
    let manifest = ObjectManifest::new("event_archive", [child], None)?;
    let _ = local.publish(&SlotName::parse(slot)?, &manifest)?;
    Ok(())
}

fn append_bytes(path: &Path, bytes: &[u8]) -> TestResult {
    OpenOptions::new()
        .append(true)
        .open(path)?
        .write_all(bytes)?;
    Ok(())
}

fn append_batch(
    path: &Path,
    lineage: &str,
    batch_id: &str,
    object: &str,
    family: &str,
) -> TestResult {
    let mut ledger = DurableReferenceLedger::open(path, lineage, IncompleteTailPolicy::Reject)?;
    let delta = EvidenceDelta {
        delta_id: format!("delta:{object}"),
        family: family.to_owned(),
        object_id: ObjectId::parse(object)?,
        prior_generation: None,
        new_generation: 1,
        validity: CaptureInterval::new(TimestampNs(100), TimestampNs(200))?,
        plane: Plane::Authority,
        payload_digest: ContentDigest::sha256(object.as_bytes()),
        witness_digest: None,
        operation_id: None,
    };
    let batch = ledger.prepare_batch(BatchId::parse(batch_id)?, vec![delta], [])?;
    let _ = ledger.append(batch)?;
    Ok(())
}

fn indeterminate_ops(dep: &Path, count: u32) -> TestResult {
    let mut journal = DurableEffectJournal::open(
        dep.join(RELATIVE_PATH_EFFECTS),
        IncompleteTailPolicy::Reject,
    )?;
    for i in 0..count {
        let op = OperationId::parse(format!("op:doctor-test:{i}"))?;
        let intent = EffectIntent {
            operation_id: op.clone(),
            idempotency_key: IdempotencyKey::parse(format!("idempotency:doctor-test:{i}"))?,
            effect_class: "alert.dispatch".to_string(),
            request_digest: ContentDigest::sha256(b"req"),
            precondition_digest: ContentDigest::sha256(b"pre"),
        };
        let obligation = ObligationId::parse(format!("obligation:doctor-test:{i}"))?;
        let _ = journal.prepare(intent, obligation, "delivery_ack", TimestampNs(100))?;
        let _ = journal.transition(&op, EffectState::Committed, TimestampNs(110), None, None)?;
        let _ = journal.mark_indeterminate(&op, TimestampNs(120), "timeout")?;
    }
    Ok(())
}

fn hex64(seed: &[u8]) -> String {
    ContentDigest::sha256(seed)
        .to_text()
        .trim_start_matches("sha256:")
        .to_owned()
}

// ---------------------------------------------------------------- read-only proof: tree digest

fn tree_digest(root: &Path) -> Res<BTreeMap<PathBuf, String>> {
    let mut out = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let meta = fs::symlink_metadata(&path)?;
        let rel = path.strip_prefix(root)?.to_path_buf();
        let common = format!(
            "mode={:o} size={} mtime={}.{} ctime={}.{} ino={} nlink={}",
            meta.mode(),
            meta.size(),
            meta.mtime(),
            meta.mtime_nsec(),
            meta.ctime(),
            meta.ctime_nsec(),
            meta.ino(),
            meta.nlink()
        );
        let detail = if meta.file_type().is_dir() {
            let mut names = Vec::new();
            for entry in fs::read_dir(&path)? {
                let entry = entry?;
                names.push(entry.file_name().to_string_lossy().into_owned());
                pending.push(entry.path());
            }
            names.sort();
            format!("dir [{}]", names.join(","))
        } else if meta.file_type().is_file() && meta.size() <= CONTENT_DIGEST_MAX {
            format!("file {}", ContentDigest::sha256(&fs::read(&path)?))
        } else {
            "large-or-special (metadata only)".to_owned()
        };
        out.insert(rel, format!("{common} {detail}"));
    }
    Ok(out)
}

fn inspect_read_only(label: &str, dep: &Path) -> Res<DoctorReport> {
    let before = tree_digest(dep)?;
    let report = inspect_deployment(dep);
    let json = report.to_json();
    let after = tree_digest(dep)?;
    if after != before {
        return Err(format!("tree changed by {label}: before={before:#?} after={after:#?}").into());
    }
    if json.contains("fss-lab") {
        return Err(
            format!("{label}: doctor printed a command that does not exist: {json}").into(),
        );
    }
    Ok(report)
}

// ---------------------------------------------------------------- expected JSON builders

fn s(value: &str) -> String {
    format!("\"{value}\"")
}

fn obj(pairs: &[(&str, String)]) -> String {
    let parts: Vec<String> = pairs.iter().map(|(k, v)| format!("\"{k}\":{v}")).collect();
    format!("{{{}}}", parts.join(","))
}

fn nums(pairs: &[(&str, u64)]) -> String {
    let parts: Vec<String> = pairs.iter().map(|(k, v)| format!("\"{k}\":{v}")).collect();
    format!("{{{}}}", parts.join(","))
}

fn list(items: &[String]) -> String {
    let parts: Vec<String> = items.iter().map(|item| s(item)).collect();
    format!("[{}]", parts.join(","))
}

fn finding(kind: &str, severity: &str, count: Option<u64>, affordance: Option<&str>) -> String {
    let mut parts = vec![
        format!("\"kind\":\"{kind}\""),
        format!("\"severity\":\"{severity}\""),
    ];
    if let Some(count) = count {
        parts.push(format!("\"count\":{count}"));
    }
    if let Some(affordance) = affordance {
        parts.push(format!("\"next_affordance\":{affordance}"));
    }
    format!("{{{}}}", parts.join(","))
}

fn check(
    id: &str,
    status: &str,
    severity: &str,
    fields: &[(&str, String)],
    findings: &[String],
    next: Option<&str>,
) -> String {
    let mut parts = vec![
        format!("\"id\":\"{id}\""),
        format!("\"status\":\"{status}\""),
        format!("\"severity\":\"{severity}\""),
    ];
    for (key, value) in fields {
        parts.push(format!("\"{key}\":{value}"));
    }
    parts.push(format!("\"findings\":[{}]", findings.join(",")));
    if let Some(next) = next {
        parts.push(format!("\"next_affordance\":{next}"));
    }
    format!("{{{}}}", parts.join(","))
}

fn not_yet(action: &str, target: Option<&str>, plan_digest: Option<&str>) -> String {
    let mut pairs = vec![
        ("availability", s("not_yet_available")),
        ("action", s(action)),
    ];
    if let Some(target) = target {
        pairs.push(("target", s(target)));
    }
    if let Some(plan_digest) = plan_digest {
        pairs.push(("plan_digest", s(plan_digest)));
    }
    pairs.push(("tracking", s(TRACKING)));
    obj(&pairs)
}

fn owner(action: &str, detail: &str) -> String {
    obj(&[
        ("availability", s("owner_decision")),
        ("action", s(action)),
        ("detail", s(detail)),
    ])
}

fn rerun(dep: &Path) -> String {
    obj(&[
        ("availability", s("available")),
        ("action", s("wait_for_writer_then_rerun_doctor")),
        (
            "command",
            s(&format!("fss doctor --json --root {}", dep.display())),
        ),
    ])
}

fn over_budget(
    id: &str,
    limit_name: &str,
    limit: u64,
    observed: u64,
    reason: Option<&str>,
) -> String {
    let aff = owner("owner_action", OVER_BUDGET_DETAIL);
    let mut fields = vec![
        ("limit_bytes", limit.to_string()),
        ("limit_name", s(limit_name)),
        ("observed_bytes", observed.to_string()),
    ];
    if let Some(reason) = reason {
        fields.push(("reason", s(reason)));
    }
    check(
        id,
        "over_budget",
        "attention",
        &fields,
        &[finding("over_budget", "attention", None, Some(&aff))],
        Some(&aff),
    )
}

struct Journal {
    bytes: Vec<u8>,
    committed_len: u64,
    records: usize,
    last_root: String,
    incomplete_tail: Option<u64>,
    foreign: Option<(u64, u64, String)>,
}

fn journal(path: &Path) -> Res<Journal> {
    let bytes = fs::read(path)?;
    let report = fss_ledger::doctor(&bytes)?;
    Ok(Journal {
        committed_len: report.committed_len(),
        records: report.records_count(),
        last_root: report.last_root().to_text(),
        incomplete_tail: report.incomplete_tail(),
        foreign: report
            .foreign_range()
            .map(|f| (f.offset(), f.length(), f.digest().to_text())),
        bytes,
    })
}

fn journal_counts(j: &Journal, tail: Option<u64>) -> String {
    let mut pairs = vec![
        ("committed_len", j.committed_len),
        ("file_len", j.bytes.len() as u64),
    ];
    if let Some(tail) = tail {
        pairs.push(("incomplete_tail_bytes", tail));
    }
    pairs.push(("records_count", j.records as u64));
    nums(&pairs)
}

fn journal_clean(id: &str, path: &Path) -> Res<String> {
    let j = journal(path)?;
    Ok(check(
        id,
        "clean",
        "ok",
        &[
            ("counts", journal_counts(&j, None)),
            (
                "evidence",
                obj(&[
                    (
                        "journal_sha256",
                        s(&ContentDigest::sha256(&j.bytes).to_text()),
                    ),
                    ("last_root", s(&j.last_root)),
                ]),
            ),
        ],
        &[],
        None,
    ))
}

fn layout_clean(dep: &Path) -> Res<String> {
    let bytes = fs::read(dep.join("LAYOUT"))?;
    let limits_digest = DeploymentLimits::standard().canonical_digest()?;
    Ok(check(
        "deployment.layout",
        "clean",
        "ok",
        &[
            (
                "evidence",
                obj(&[
                    ("layout_sha256", s(&ContentDigest::sha256(&bytes).to_text())),
                    ("limits_digest", s(&limits_digest.to_text())),
                ]),
            ),
            ("format_version", "1".to_owned()),
            ("limits_profile", s("standard")),
            ("site_lineage", s(LINEAGE)),
        ],
        &[],
        None,
    ))
}

fn writer_clean() -> String {
    check(
        "deployment.writer",
        "clean",
        "ok",
        &[
            ("possibly_stale", "false".to_owned()),
            ("probe_method", s("proc_locks")),
            ("probe_scope", s("this_host_this_pid_namespace")),
            ("writer_state", s("not_observed")),
            ("writer_state_after", s("not_observed")),
        ],
        &[],
        None,
    )
}

fn obligations_counts(total: u64, pending: u64, indeterminate: u64, ops: u64) -> String {
    nums(&[
        ("cancelled", 0),
        ("failed", 0),
        ("indeterminate", indeterminate),
        ("indeterminate_operations", ops),
        ("pending", pending),
        ("terminal", 0),
        ("total", total),
        ("verified", 0),
    ])
}

fn roots_counts(visible: u64, broken: u64, pending: u64, temps: u64) -> String {
    nums(&[
        ("broken_roots", broken),
        ("ledgered_roots", 0),
        ("not_durable_roots", 0),
        ("orphaned_root_temps", temps),
        ("pending_roots", pending),
        ("slot_conflicts", 0),
        ("unbacked_claims", 0),
        ("unledgerable_roots", 0),
        ("visible_roots", visible),
    ])
}

fn spool_counts(admitted: u64, corrupt: u64, spool_foreign: u64) -> String {
    nums(&[
        ("admitted", admitted),
        ("corrupt_objects", corrupt),
        ("publication_foreign_entries", 0),
        ("spool_foreign_entries", spool_foreign),
    ])
}

fn sidecars_clean(id: &str) -> String {
    check(
        id,
        "clean",
        "ok",
        &[(
            "counts",
            nums(&[("leftover_repair_temps", 0), ("quarantine_sidecars", 0)]),
        )],
        &[],
        None,
    )
}

/// The exact report of a clean deployment; tests replace the checks their fault changes.
struct Expect {
    root: PathBuf,
    verdict: &'static str,
    possibly_stale: bool,
    limits: String,
    checks: Vec<(String, String)>,
}

impl Expect {
    fn clean(dep: &Path) -> Res<Self> {
        let checks = vec![
            ("deployment.layout", layout_clean(dep)?),
            ("deployment.writer", writer_clean()),
            (
                "ledger.journal",
                journal_clean("ledger.journal", &dep.join(RELATIVE_PATH_LEDGER))?,
            ),
            (
                "effects.journal",
                journal_clean("effects.journal", &dep.join(RELATIVE_PATH_EFFECTS))?,
            ),
            (
                "effects.obligations",
                check(
                    "effects.obligations",
                    "clean",
                    "ok",
                    &[("counts", obligations_counts(0, 0, 0, 0))],
                    &[],
                    None,
                ),
            ),
            (
                "publication.staging",
                check(
                    "publication.staging",
                    "clean",
                    "ok",
                    &[(
                        "counts",
                        nums(&[("orphaned_staging", 0), ("orphaned_staging_bytes", 0)]),
                    )],
                    &[],
                    None,
                ),
            ),
            (
                "objects.spool",
                check(
                    "objects.spool",
                    "clean",
                    "ok",
                    &[("counts", spool_counts(0, 0, 0))],
                    &[],
                    None,
                ),
            ),
            (
                "publication.roots",
                check(
                    "publication.roots",
                    "clean",
                    "ok",
                    &[
                        ("counts", roots_counts(0, 0, 0, 0)),
                        ("linkage_state", s("inspected")),
                    ],
                    &[],
                    None,
                ),
            ),
            (
                "objects.unreferenced",
                check(
                    "objects.unreferenced",
                    "clean",
                    "ok",
                    &[("counts", nums(&[("unreferenced_objects", 0)]))],
                    &[],
                    None,
                ),
            ),
            (
                "objects.tombstones",
                check(
                    "objects.tombstones",
                    "clean",
                    "ok",
                    &[("counts", nums(&[("tombstones", 0)]))],
                    &[],
                    None,
                ),
            ),
            (
                "imports.incomplete",
                check(
                    "imports.incomplete",
                    "clean",
                    "ok",
                    &[("counts", nums(&[("imports", 0), ("incomplete_imports", 0)]))],
                    &[],
                    None,
                ),
            ),
            ("ledger.sidecars", sidecars_clean("ledger.sidecars")),
            ("effects.sidecars", sidecars_clean("effects.sidecars")),
        ];
        Ok(Self {
            root: dep.to_path_buf(),
            verdict: "healthy",
            possibly_stale: false,
            limits: DEFAULT_LIMITS_JSON.to_owned(),
            checks: checks
                .into_iter()
                .map(|(id, json)| (id.to_owned(), json))
                .collect(),
        })
    }

    fn attention(mut self) -> Self {
        self.verdict = "attention_required";
        self
    }

    fn set(&mut self, id: &str, json: String) -> TestResult {
        let slot = self
            .checks
            .iter_mut()
            .find(|(check_id, _)| check_id == id)
            .ok_or_else(|| format!("no check {id}"))?;
        slot.1 = json;
        Ok(())
    }

    fn json(&self) -> String {
        let checks: Vec<&str> = self.checks.iter().map(|(_, json)| json.as_str()).collect();
        format!(
            "{{\"schema\":\"fss.doctor.v1\",\"version\":\"{}\",\"root\":\"{}\",\"verdict\":\"{}\",\"possibly_stale\":{},\"limits\":{},\"checks\":[{}]}}",
            env!("CARGO_PKG_VERSION"),
            self.root.display(),
            self.verdict,
            self.possibly_stale,
            self.limits,
            checks.join(",")
        )
    }
}

fn check_json(report: &DoctorReport, id: &str) -> Res<String> {
    Ok(report
        .check(id)
        .ok_or_else(|| format!("missing check {id}"))?
        .to_json())
}

fn statuses(report: &DoctorReport) -> Vec<(String, String)> {
    report
        .checks
        .iter()
        .map(|c| (c.id.clone(), c.status.clone()))
        .collect()
}

fn clean_statuses_except(overrides: &[(&str, &str)]) -> Vec<(String, String)> {
    let ids = [
        "deployment.layout",
        "deployment.writer",
        "ledger.journal",
        "effects.journal",
        "effects.obligations",
        "publication.staging",
        "objects.spool",
        "publication.roots",
        "objects.unreferenced",
        "objects.tombstones",
        "imports.incomplete",
        "ledger.sidecars",
        "effects.sidecars",
    ];
    ids.iter()
        .map(|id| {
            let status = overrides
                .iter()
                .find(|(o, _)| o == id)
                .map_or("clean", |(_, status)| status);
            ((*id).to_owned(), status.to_owned())
        })
        .collect()
}

// ---------------------------------------------------------------- read-only proof: I/O seam

#[derive(Default)]
struct RecordingJournalIo {
    largest_request: Mutex<usize>,
    reads: Mutex<usize>,
}

impl JournalReadIo for RecordingJournalIo {
    fn symlink_metadata(&self, path: &Path) -> io::Result<JournalFileMetadata> {
        HostJournalReadIo.symlink_metadata(path)
    }

    fn read_bounded(&self, path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
        if let Ok(mut largest) = self.largest_request.lock() {
            *largest = (*largest).max(max_bytes);
        }
        if let Ok(mut reads) = self.reads.lock() {
            *reads += 1;
        }
        HostJournalReadIo.read_bounded(path, max_bytes)
    }
}

/// Wraps the host lock table; on every read it records each `FLOCK` entry owned by this process
/// on one of the deployment's lock files. The doctor holds no lock, so the record stays empty.
#[derive(Debug)]
struct SpyLockTable {
    targets: Vec<(u32, u32, u64)>,
    reads: Mutex<usize>,
    own_locks: Mutex<Vec<String>>,
}

impl SpyLockTable {
    fn new(lock_files: &[PathBuf]) -> Res<Self> {
        let mut targets = Vec::new();
        for path in lock_files {
            let meta = fs::metadata(path)?;
            let (major, minor) = decode_st_dev(meta.dev());
            targets.push((major, minor, meta.ino()));
        }
        Ok(Self {
            targets,
            reads: Mutex::new(0),
            own_locks: Mutex::new(Vec::new()),
        })
    }

    fn owns_target_lock(&self, line: &str) -> bool {
        let tokens: Vec<&str> = line.split_whitespace().filter(|t| *t != "->").collect();
        let (Some(pid), Some(dev_ino)) = (tokens.get(4), tokens.get(5)) else {
            return false;
        };
        if pid.parse::<u32>().ok() != Some(std::process::id()) {
            return false;
        }
        let parts: Vec<&str> = dev_ino.split(':').collect();
        let [major, minor, ino] = parts.as_slice() else {
            return false;
        };
        match (
            u32::from_str_radix(major, 16),
            u32::from_str_radix(minor, 16),
            ino.parse::<u64>(),
        ) {
            (Ok(major), Ok(minor), Ok(ino)) => self.targets.contains(&(major, minor, ino)),
            _ => false,
        }
    }

    fn reads(&self) -> usize {
        self.reads.lock().map(|r| *r).unwrap_or(0)
    }

    fn own_locks(&self) -> Vec<String> {
        self.own_locks.lock().map(|l| l.clone()).unwrap_or_default()
    }

    fn clear(&self) {
        if let Ok(mut locks) = self.own_locks.lock() {
            locks.clear();
        }
        if let Ok(mut reads) = self.reads.lock() {
            *reads = 0;
        }
    }
}

impl LockTableSource for SpyLockTable {
    fn read_lock_table(&self, max_bytes: usize) -> io::Result<String> {
        let table = HostLockTableSource.read_lock_table(max_bytes)?;
        for line in table.lines() {
            if self.owns_target_lock(line)
                && let Ok(mut locks) = self.own_locks.lock()
            {
                locks.push(line.to_owned());
            }
        }
        if let Ok(mut reads) = self.reads.lock() {
            *reads += 1;
        }
        Ok(table)
    }
}

fn lock_files(dep: &Path) -> Vec<PathBuf> {
    let objects = dep.join(RELATIVE_PATH_OBJECTS);
    vec![
        objects.join(LOCAL_LOCK_FILE),
        objects.join(LOCAL_SPOOL_DIR).join(SPOOL_LOCK_FILE),
        dep.join(RELATIVE_PATH_LEDGER),
        dep.join(RELATIVE_PATH_EFFECTS),
    ]
}

// ---------------------------------------------------------------- tests

#[test]
fn clean_reference_deployment_is_healthy_exact_json() -> TestResult {
    let dep = init("clean")?;
    let report = inspect_read_only("clean", &dep)?;
    assert_eq!(report.to_json(), Expect::clean(&dep)?.json());
    assert_eq!(report.verdict, DoctorVerdict::Healthy);
    assert_eq!(report.exit_code(), 0);
    Ok(())
}

#[test]
fn inspection_takes_no_lock_and_makes_no_mutating_call() -> TestResult {
    let dep = init("no_lock")?;
    let spy = SpyLockTable::new(&lock_files(&dep))?;

    // The spy must see a lock this process holds on a target, or its empty record proves nothing.
    let holder = fs::File::open(dep.join(RELATIVE_PATH_OBJECTS).join(LOCAL_LOCK_FILE))?;
    holder.try_lock()?;
    let _ = spy.read_lock_table(1 << 20)?;
    assert_eq!(
        spy.own_locks().len(),
        1,
        "spy failed to see a held target lock"
    );
    drop(holder);
    spy.clear();

    let recording = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let files = RecordingJournalIo::default();
    let io = DoctorIo {
        fs: &recording,
        files: &files,
        lock_table: &spy,
    };
    let before = tree_digest(&dep)?;
    let report = inspect_deployment_with(&dep, io, DoctorLimits::default());
    assert_eq!(tree_digest(&dep)?, before);

    assert_eq!(recording.mutating_calls(), Vec::new());
    assert!(recording.is_read_only());
    assert!(
        spy.reads() >= 2,
        "the writer must be observed before and after the journals"
    );
    assert_eq!(spy.own_locks(), Vec::<String>::new());
    let largest = files
        .largest_request
        .lock()
        .map(|l| *l)
        .unwrap_or(usize::MAX);
    assert!(largest <= DoctorLimits::default().max_journal_bytes + 1);
    assert_eq!(
        files.reads.lock().map(|r| *r).unwrap_or(0),
        3,
        "LAYOUT and each journal once"
    );
    assert_eq!(report.to_json(), Expect::clean(&dep)?.json());
    Ok(())
}

#[test]
fn ledger_incomplete_tail_is_attention_with_named_truncate_action() -> TestResult {
    let dep = init("ledger_tail")?;
    let ledger_path = dep.join(RELATIVE_PATH_LEDGER);
    append_batch(
        &ledger_path,
        LINEAGE,
        "batch:tail",
        "obj:tail",
        "sensor_capsule",
    )?;
    let head = fs::read(&ledger_path)?;
    append_bytes(&ledger_path, head.get(..16).ok_or("short ledger")?)?;

    let report = inspect_read_only("ledger tail", &dep)?;
    let j = journal(&ledger_path)?;
    let tail = j.incomplete_tail.ok_or("no incomplete tail")?;
    let aff = not_yet("truncate_incomplete_tail", Some("ledger"), None);
    let mut expected = Expect::clean(&dep)?.attention();
    expected.set(
        "ledger.journal",
        check(
            "ledger.journal",
            "incomplete_tail",
            "attention",
            &[
                (
                    "counts",
                    journal_counts(&j, Some(j.bytes.len() as u64 - tail)),
                ),
                (
                    "evidence",
                    obj(&[
                        (
                            "journal_sha256",
                            s(&ContentDigest::sha256(&j.bytes).to_text()),
                        ),
                        ("last_root", s(&j.last_root)),
                    ]),
                ),
                ("incomplete_tail_offset", tail.to_string()),
            ],
            &[finding("incomplete_tail", "attention", None, Some(&aff))],
            Some(&aff),
        ),
    )?;
    assert_eq!(report.to_json(), expected.json());
    assert_eq!(report.exit_code(), 3);
    Ok(())
}

#[test]
fn effects_incomplete_tail_is_attention_with_named_truncate_action() -> TestResult {
    let dep = init("effects_tail")?;
    let effects_path = dep.join(RELATIVE_PATH_EFFECTS);
    append_bytes(&effects_path, b"FSSJRN01")?;

    let report = inspect_read_only("effects tail", &dep)?;
    let j = journal(&effects_path)?;
    let tail = j.incomplete_tail.ok_or("no incomplete tail")?;
    let aff = not_yet("truncate_incomplete_tail", Some("effects"), None);
    let mut expected = Expect::clean(&dep)?.attention();
    expected.set(
        "effects.journal",
        check(
            "effects.journal",
            "incomplete_tail",
            "attention",
            &[
                (
                    "counts",
                    journal_counts(&j, Some(j.bytes.len() as u64 - tail)),
                ),
                (
                    "evidence",
                    obj(&[
                        (
                            "journal_sha256",
                            s(&ContentDigest::sha256(&j.bytes).to_text()),
                        ),
                        ("last_root", s(&j.last_root)),
                    ]),
                ),
                ("incomplete_tail_offset", tail.to_string()),
            ],
            &[finding("incomplete_tail", "attention", None, Some(&aff))],
            Some(&aff),
        ),
    )?;
    assert_eq!(report.to_json(), expected.json());
    Ok(())
}

fn foreign_check(id: &str, path: &Path, action: &str, target: &str) -> Res<String> {
    let j = journal(path)?;
    let (offset, length, digest) = j.foreign.clone().ok_or("no foreign range")?;
    let plan = fss_ledger::doctor(&j.bytes)?
        .plan(path)?
        .plan_digest()
        .to_string();
    let aff = not_yet(action, Some(target), Some(&plan));
    Ok(check(
        id,
        "foreign_trailing_bytes",
        "attention",
        &[
            ("counts", journal_counts(&j, None)),
            (
                "evidence",
                obj(&[
                    ("foreign_digest", s(&digest)),
                    (
                        "journal_sha256",
                        s(&ContentDigest::sha256(&j.bytes).to_text()),
                    ),
                    ("last_root", s(&j.last_root)),
                ]),
            ),
            ("foreign_length", length.to_string()),
            ("foreign_offset", offset.to_string()),
            ("plan_digest", s(&plan)),
        ],
        &[finding(
            "foreign_trailing_bytes",
            "attention",
            None,
            Some(&aff),
        )],
        Some(&aff),
    ))
}

#[test]
fn ledger_foreign_bytes_name_the_plan_digest() -> TestResult {
    let dep = init("ledger_foreign")?;
    let ledger_path = dep.join(RELATIVE_PATH_LEDGER);
    append_bytes(&ledger_path, b"FOREIGN_GARBAGE_BYTES_WITHOUT_MAGIC")?;
    let report = inspect_read_only("ledger foreign", &dep)?;
    let mut expected = Expect::clean(&dep)?.attention();
    expected.set(
        "ledger.journal",
        foreign_check(
            "ledger.journal",
            &ledger_path,
            "plan_ledger_repair_then_apply_ledger_repair",
            "ledger",
        )?,
    )?;
    assert_eq!(report.to_json(), expected.json());
    Ok(())
}

#[test]
fn effects_foreign_bytes_name_the_effects_repair_plan() -> TestResult {
    let dep = init("effects_foreign")?;
    let effects_path = dep.join(RELATIVE_PATH_EFFECTS);
    append_bytes(&effects_path, b"FOREIGN_GARBAGE_BYTES_WITHOUT_MAGIC")?;
    let report = inspect_read_only("effects foreign", &dep)?;
    let mut expected = Expect::clean(&dep)?.attention();
    expected.set(
        "effects.journal",
        foreign_check(
            "effects.journal",
            &effects_path,
            "plan_effects_repair_then_apply_effects_repair",
            "effects",
        )?,
    )?;
    assert_eq!(report.to_json(), expected.json());
    Ok(())
}

#[test]
fn corrupt_history_is_an_owner_action_never_a_repair() -> TestResult {
    let dep = init("corrupt_history")?;
    let ledger_path = dep.join(RELATIVE_PATH_LEDGER);
    let donor = fresh("corrupt_history_donor")?.join("journal.fssj");
    append_batch(
        &donor,
        LINEAGE,
        "batch:corrupt",
        "obj:corrupt",
        "sensor_capsule",
    )?;
    let mut tail = b"NON_MAGIC_PAD_BYTES_".to_vec();
    tail.extend_from_slice(&fs::read(&donor)?);
    append_bytes(&ledger_path, &tail)?;

    let report = inspect_read_only("corrupt history", &dep)?;
    let j = journal(&ledger_path)?;
    let (offset, length, digest) = j.foreign.clone().ok_or("no foreign range")?;
    let aff = owner(
        "owner_action",
        "a structurally valid record lies inside the foreign range; foreign-byte repair must not be applied",
    );
    let mut expected = Expect::clean(&dep)?.attention();
    expected.set(
        "ledger.journal",
        check(
            "ledger.journal",
            "corrupt_history",
            "attention",
            &[
                ("counts", journal_counts(&j, None)),
                (
                    "evidence",
                    obj(&[
                        ("foreign_digest", s(&digest)),
                        (
                            "journal_sha256",
                            s(&ContentDigest::sha256(&j.bytes).to_text()),
                        ),
                        ("last_root", s(&j.last_root)),
                    ]),
                ),
                ("foreign_length", length.to_string()),
                ("foreign_offset", offset.to_string()),
                ("valid_record_offset", (offset + 20).to_string()),
            ],
            &[finding("corrupt_history", "attention", None, Some(&aff))],
            Some(&aff),
        ),
    )?;
    assert_eq!(report.to_json(), expected.json());
    Ok(())
}

#[test]
fn live_reference_deployment_writer_is_held_and_tail_is_in_flight() -> TestResult {
    let dep = fresh("live_writer")?;
    let deployment = ReferenceDeployment::open(&dep, LINEAGE, &test_cx("live_writer")?)?;
    let ledger_path = dep.join(RELATIVE_PATH_LEDGER);
    append_bytes(&ledger_path, b"FSSJRN01")?;

    let report = inspect_read_only("live writer", &dep)?;
    let j = journal(&ledger_path)?;
    let tail = j.incomplete_tail.ok_or("no incomplete tail")?;
    let aff = rerun(&dep);
    let mut expected = Expect::clean(&dep)?;
    expected.possibly_stale = true;
    expected.set(
        "deployment.writer",
        check(
            "deployment.writer",
            "concurrent_writer",
            "info",
            &[
                ("pid_hint", std::process::id().to_string()),
                ("possibly_stale", "true".to_owned()),
                ("probe_method", s("proc_locks")),
                ("writer_state", s("held")),
                ("writer_state_after", s("held")),
            ],
            &[finding("concurrent_writer", "info", None, Some(&aff))],
            Some(&aff),
        ),
    )?;
    expected.set(
        "ledger.journal",
        check(
            "ledger.journal",
            "possibly_in_flight",
            "info",
            &[
                (
                    "counts",
                    journal_counts(&j, Some(j.bytes.len() as u64 - tail)),
                ),
                (
                    "evidence",
                    obj(&[
                        (
                            "journal_sha256",
                            s(&ContentDigest::sha256(&j.bytes).to_text()),
                        ),
                        ("last_root", s(&j.last_root)),
                    ]),
                ),
                ("incomplete_tail_offset", tail.to_string()),
            ],
            &[finding("possibly_in_flight", "info", None, Some(&aff))],
            Some(&aff),
        ),
    )?;
    assert_eq!(report.to_json(), expected.json());
    // Writer presence alone does not change the exit code (round 3 default); it marks staleness.
    assert_eq!(report.exit_code(), 0);
    drop(deployment);
    Ok(())
}

#[test]
fn undetermined_writer_state_is_unknown_never_clean() -> TestResult {
    let dep = init("writer_unknown")?;
    let table = StringLockTableSource("not a lock table".to_owned());
    let io = DoctorIo {
        fs: &HostSpoolIo,
        files: &HostJournalReadIo,
        lock_table: &table,
    };
    let report = inspect_deployment_with(&dep, io, DoctorLimits::default());
    let aff = owner(
        "restore_lock_table_access",
        "writer presence could not be determined; the snapshot may be stale",
    );
    let mut expected = Expect::clean(&dep)?.attention();
    expected.possibly_stale = true;
    expected.set(
        "deployment.writer",
        check(
            "deployment.writer",
            "unknown",
            "attention",
            &[
                ("possibly_stale", "true".to_owned()),
                ("probe_method", s("proc_locks")),
                ("reason", s("parse_error")),
                ("writer_state", s("unknown")),
                ("writer_state_after", s("unknown")),
            ],
            &[finding("unknown", "attention", None, Some(&aff))],
            Some(&aff),
        ),
    )?;
    assert_eq!(report.to_json(), expected.json());
    assert_eq!(report.exit_code(), 3);
    Ok(())
}

#[test]
fn invalid_lock_layout_is_reported_typed() -> TestResult {
    let dep = init("writer_invalid_layout")?;
    let lock = dep.join(RELATIVE_PATH_OBJECTS).join(LOCAL_LOCK_FILE);
    fs::remove_file(&lock)?;
    fs::create_dir(&lock)?;
    let report = inspect_read_only("invalid lock layout", &dep)?;
    let aff = owner(
        "inspect_lock_files",
        "a lock path is not a regular file; writers cannot be observed until it is restored",
    );
    assert_eq!(
        check_json(&report, "deployment.writer")?,
        check(
            "deployment.writer",
            "invalid_layout",
            "attention",
            &[
                ("possibly_stale", "true".to_owned()),
                ("probe_method", s("non_regular_lock_file")),
                ("writer_state", s("invalid_layout")),
                ("writer_state_after", s("invalid_layout")),
            ],
            &[finding("invalid_layout", "attention", None, Some(&aff))],
            Some(&aff),
        )
    );
    assert_eq!(report.verdict, DoctorVerdict::AttentionRequired);
    assert!(report.possibly_stale);
    Ok(())
}

#[test]
fn orphaned_staging_is_listed_with_discard_action() -> TestResult {
    let dep = init("orphaned_staging")?;
    let staging = dep
        .join(RELATIVE_PATH_OBJECTS)
        .join(LOCAL_SPOOL_DIR)
        .join("staging");
    let name = format!("{}.0.tmp", hex64(b"staging-data"));
    fs::write(staging.join(&name), b"staging-data")?;

    let report = inspect_read_only("orphaned staging", &dep)?;
    let aff = not_yet("discard_orphaned_staging", Some("objects"), None);
    let mut expected = Expect::clean(&dep)?.attention();
    expected.set(
        "publication.staging",
        check(
            "publication.staging",
            "orphaned_staging",
            "attention",
            &[
                (
                    "counts",
                    nums(&[("orphaned_staging", 1), ("orphaned_staging_bytes", 12)]),
                ),
                ("orphaned_staging", list(&[format!("staging/{name}")])),
                ("orphaned_staging_total", "1".to_owned()),
            ],
            &[finding(
                "orphaned_staging",
                "attention",
                Some(1),
                Some(&aff),
            )],
            Some(&aff),
        ),
    )?;
    assert_eq!(report.to_json(), expected.json());
    Ok(())
}

#[test]
fn orphaned_root_temps_are_listed_with_discard_action() -> TestResult {
    let dep = init("orphaned_root_temps")?;
    let name = format!("slot_test{ROOT_RECORD_SUFFIX}{ROOT_TEMP_SUFFIX}");
    fs::write(
        dep.join(RELATIVE_PATH_OBJECTS)
            .join(LOCAL_ROOTS_DIR)
            .join(&name),
        b"temp-root",
    )?;
    let report = inspect_read_only("orphaned root temps", &dep)?;
    let aff = not_yet("discard_orphaned_temps", Some("objects"), None);
    let mut expected = Expect::clean(&dep)?.attention();
    expected.set(
        "publication.roots",
        check(
            "publication.roots",
            "orphaned_root_temps",
            "attention",
            &[
                ("counts", roots_counts(0, 0, 0, 1)),
                ("linkage_state", s("inspected")),
                (
                    "orphaned_root_temps",
                    list(&[format!("{LOCAL_ROOTS_DIR}/{name}")]),
                ),
                ("orphaned_root_temps_total", "1".to_owned()),
            ],
            &[finding(
                "orphaned_root_temps",
                "attention",
                Some(1),
                Some(&aff),
            )],
            Some(&aff),
        ),
    )?;
    assert_eq!(report.to_json(), expected.json());
    Ok(())
}

#[test]
fn broken_root_is_reported_and_its_objects_unreferenced() -> TestResult {
    let dep = init("broken_root")?;
    publish(&dep, "broken_slot")?;
    fs::write(
        dep.join(RELATIVE_PATH_OBJECTS)
            .join(LOCAL_ROOTS_DIR)
            .join(format!("broken_slot{ROOT_RECORD_SUFFIX}")),
        b"garbage-root-record",
    )?;
    let report = inspect_read_only("broken root", &dep)?;
    let aff = owner(
        "owner_action",
        "broken root records are never admitted; inspecting or restoring them is an owner decision",
    );
    assert_eq!(
        check_json(&report, "publication.roots")?,
        check(
            "publication.roots",
            "broken_roots",
            "attention",
            &[
                ("broken_slots", list(&["broken_slot".to_owned()])),
                ("broken_slots_total", "1".to_owned()),
                ("counts", roots_counts(0, 1, 0, 0)),
                ("linkage_state", s("inspected")),
            ],
            &[finding("broken_roots", "attention", Some(1), Some(&aff))],
            Some(&aff),
        )
    );
    assert_eq!(
        statuses(&report),
        clean_statuses_except(&[
            ("publication.roots", "broken_roots"),
            ("objects.unreferenced", "unreferenced_objects"),
        ])
    );
    assert_eq!(report.exit_code(), 3);
    Ok(())
}

#[test]
fn pending_root_names_the_producing_command_as_owner_decision() -> TestResult {
    let dep = init("pending_root")?;
    publish(&dep, "pending_slot")?;
    let report = inspect_read_only("pending root", &dep)?;
    let aff = owner(
        "rerun_producing_command",
        "rerun the command that produced the root; an explicit ledger commit is an owner decision",
    );
    assert_eq!(
        check_json(&report, "publication.roots")?,
        check(
            "publication.roots",
            "pending_roots",
            "attention",
            &[
                ("counts", roots_counts(1, 0, 1, 0)),
                ("linkage_state", s("inspected")),
                ("pending_slots", list(&["pending_slot".to_owned()])),
                ("pending_slots_total", "1".to_owned()),
            ],
            &[finding("pending_roots", "attention", Some(1), Some(&aff))],
            Some(&aff),
        )
    );
    assert_eq!(
        statuses(&report),
        clean_statuses_except(&[("publication.roots", "pending_roots")])
    );
    Ok(())
}

#[test]
fn failed_linkage_replay_is_unknown_never_clean() -> TestResult {
    let dep = init("linkage_unknown")?;
    let ledger_path = dep.join(RELATIVE_PATH_LEDGER);
    fs::remove_file(&ledger_path)?;
    append_batch(
        &ledger_path,
        "site:other-lineage",
        "batch:other",
        "obj:other",
        "sensor_capsule",
    )?;
    publish(&dep, "pending_slot")?;
    let replay_error =
        match fss_ledger::inspect_durable(&ledger_path, LINEAGE, DurableLedgerLimits::default()) {
            Ok(_) => return Err("replay under the layout lineage unexpectedly succeeded".into()),
            Err(error) => format!("ledger replay failed: {error}"),
        };

    let report = inspect_read_only("linkage unknown", &dep)?;
    let linkage_aff = owner(
        "owner_action",
        "root-ledger linkage could not be determined; pending roots, unbacked claims, and slot conflicts are unknown",
    );
    assert_eq!(
        check_json(&report, "publication.roots")?,
        check(
            "publication.roots",
            "linkage_unknown",
            "attention",
            &[
                (
                    "counts",
                    nums(&[
                        ("broken_roots", 0),
                        ("orphaned_root_temps", 0),
                        ("visible_roots", 1)
                    ]),
                ),
                ("linkage_reason", s(&replay_error)),
                ("linkage_state", s("unknown")),
            ],
            &[finding(
                "linkage_unknown",
                "attention",
                None,
                Some(&linkage_aff)
            )],
            Some(&linkage_aff),
        )
    );
    let imports_aff = owner(
        "owner_action",
        "the ledger could not be replayed; import completeness is unknown",
    );
    assert_eq!(
        check_json(&report, "imports.incomplete")?,
        check(
            "imports.incomplete",
            "unknown",
            "attention",
            &[("reason", s(&replay_error))],
            &[finding("unknown", "attention", None, Some(&imports_aff))],
            Some(&imports_aff),
        )
    );
    Ok(())
}

fn indeterminate_check(ids: &[String], total: u64) -> String {
    let aff = not_yet("reconcile_effects", Some("effects"), None);
    let mut fields = vec![
        ("counts", obligations_counts(total, 0, total, total)),
        ("indeterminate_operations", list(ids)),
    ];
    if (ids.len() as u64) < total {
        let last = ids.last().cloned().unwrap_or_default();
        fields.push((
            "indeterminate_operations_continuation",
            obj(&[
                ("omitted", (total - ids.len() as u64).to_string()),
                ("resume_after", s(&last)),
            ]),
        ));
    }
    fields.push(("indeterminate_operations_total", total.to_string()));
    fields.push(("reconcile_affordance", s("affordance:alert:reconcile")));
    check(
        "effects.obligations",
        "indeterminate_obligations",
        "attention",
        &fields,
        &[finding(
            "indeterminate_obligations",
            "attention",
            Some(total),
            Some(&aff),
        )],
        Some(&aff),
    )
}

#[test]
fn indeterminate_obligation_is_listed_with_reconcile_action() -> TestResult {
    let dep = init("indeterminate")?;
    indeterminate_ops(&dep, 1)?;
    let report = inspect_read_only("indeterminate", &dep)?;
    let mut expected = Expect::clean(&dep)?.attention();
    expected.set(
        "effects.journal",
        journal_clean("effects.journal", &dep.join(RELATIVE_PATH_EFFECTS))?,
    )?;
    expected.set(
        "effects.obligations",
        indeterminate_check(&["op:doctor-test:0".to_owned()], 1),
    )?;
    assert_eq!(report.to_json(), expected.json());
    Ok(())
}

#[test]
fn id_lists_are_bounded_with_total_and_continuation() -> TestResult {
    let dep = init("bounded_ids")?;
    indeterminate_ops(&dep, 80)?;
    let report = inspect_read_only("bounded ids", &dep)?;
    let mut all: Vec<String> = (0..80).map(|i| format!("op:doctor-test:{i}")).collect();
    all.sort();
    let listed: Vec<String> = all.into_iter().take(32).collect();
    assert_eq!(
        check_json(&report, "effects.obligations")?,
        indeterminate_check(&listed, 80)
    );
    Ok(())
}

#[test]
fn oversize_ledger_is_over_budget_naming_the_limit() -> TestResult {
    let dep = init("oversize_ledger")?;
    let ledger_path = dep.join(RELATIVE_PATH_LEDGER);
    let oversize = 65 * 1024 * 1024;
    OpenOptions::new()
        .write(true)
        .open(&ledger_path)?
        .set_len(oversize)?;
    let report = inspect_read_only("oversize ledger", &dep)?;
    let reason = format!("ledger journal exceeds max_journal_bytes ({oversize} > 67108864 bytes)");
    let mut expected = Expect::clean(&dep)?.attention();
    expected.set(
        "ledger.journal",
        over_budget(
            "ledger.journal",
            "max_journal_bytes",
            67_108_864,
            oversize,
            None,
        ),
    )?;
    let linkage_aff = owner(
        "owner_action",
        "root-ledger linkage could not be determined; pending roots, unbacked claims, and slot conflicts are unknown",
    );
    expected.set(
        "publication.roots",
        check(
            "publication.roots",
            "linkage_unknown",
            "attention",
            &[
                (
                    "counts",
                    nums(&[
                        ("broken_roots", 0),
                        ("orphaned_root_temps", 0),
                        ("visible_roots", 0),
                    ]),
                ),
                ("linkage_reason", s(&reason)),
                ("linkage_state", s("unknown")),
            ],
            &[finding(
                "linkage_unknown",
                "attention",
                None,
                Some(&linkage_aff),
            )],
            Some(&linkage_aff),
        ),
    )?;
    let imports_aff = owner(
        "owner_action",
        "the ledger could not be replayed; import completeness is unknown",
    );
    expected.set(
        "imports.incomplete",
        check(
            "imports.incomplete",
            "unknown",
            "attention",
            &[("reason", s(&reason))],
            &[finding("unknown", "attention", None, Some(&imports_aff))],
            Some(&imports_aff),
        ),
    )?;
    assert_eq!(report.to_json(), expected.json());
    Ok(())
}

#[test]
fn oversize_effects_journal_is_over_budget_for_journal_and_obligations() -> TestResult {
    let dep = init("oversize_effects")?;
    append_bytes(&dep.join(RELATIVE_PATH_EFFECTS), &[0x5a; 32])?;
    let limits = DoctorLimits {
        max_journal_bytes: 16,
        ..DoctorLimits::default()
    };
    let before = tree_digest(&dep)?;
    let report = inspect_deployment_with(&dep, DoctorIo::host(), limits);
    assert_eq!(tree_digest(&dep)?, before);
    let mut expected = Expect::clean(&dep)?.attention();
    expected.limits = "{\"max_journal_bytes\":16,\"max_layout_bytes\":4096,\"max_listed_ids\":32,\"max_sidecar_entries\":4096}".to_owned();
    expected.set(
        "effects.journal",
        over_budget("effects.journal", "max_journal_bytes", 16, 32, None),
    )?;
    expected.set(
        "effects.obligations",
        over_budget(
            "effects.obligations",
            "max_journal_bytes",
            16,
            32,
            Some("effects journal exceeds max_journal_bytes"),
        ),
    )?;
    assert_eq!(report.to_json(), expected.json());
    Ok(())
}

#[test]
fn oversize_layout_is_over_budget_and_never_read() -> TestResult {
    let dep = init("oversize_layout")?;
    fs::write(dep.join("LAYOUT"), vec![b'x'; 5000])?;
    let report = inspect_read_only("oversize layout", &dep)?;
    let mut expected = Expect::clean(&dep)?.attention();
    expected.checks = vec![(
        "deployment.layout".to_owned(),
        over_budget("deployment.layout", "max_layout_bytes", 4096, 5000, None),
    )];
    assert_eq!(report.to_json(), expected.json());
    assert_eq!(report.exit_code(), 3);
    Ok(())
}

#[test]
fn repair_sidecars_are_split_by_journal() -> TestResult {
    let dep = init("sidecars")?;
    let ledger_dir = dep.join("ledger");
    let effects_dir = dep.join("effects");
    let quarantined = hex64(b"quarantined");
    let ledger_temp = format!("{}.tmp.1234.0", hex64(b"ledger-temp"));
    let effects_temp = format!("{}.tmp.99.1", hex64(b"effects-temp"));
    fs::write(ledger_dir.join(format!("{quarantined}.quarantine")), b"q")?;
    fs::write(ledger_dir.join(&ledger_temp), b"t")?;
    fs::write(effects_dir.join(&effects_temp), b"t")?;

    let report = inspect_read_only("sidecars", &dep)?;
    let ledger_aff = not_yet("rerun_apply_ledger_repair", Some("ledger"), None);
    let effects_aff = not_yet("rerun_apply_effects_repair", Some("effects"), None);
    let mut expected = Expect::clean(&dep)?.attention();
    expected.set(
        "ledger.sidecars",
        check(
            "ledger.sidecars",
            "leftover_repair_temps",
            "attention",
            &[
                (
                    "counts",
                    nums(&[("leftover_repair_temps", 1), ("quarantine_sidecars", 1)]),
                ),
                ("leftover_repair_temps", list(&[ledger_temp])),
                ("leftover_repair_temps_total", "1".to_owned()),
                (
                    "quarantined_digests",
                    list(&[format!("sha256:{quarantined}")]),
                ),
                ("quarantined_digests_total", "1".to_owned()),
            ],
            &[
                finding(
                    "leftover_repair_temps",
                    "attention",
                    Some(1),
                    Some(&ledger_aff),
                ),
                finding("quarantine_sidecars", "info", Some(1), None),
            ],
            Some(&ledger_aff),
        ),
    )?;
    expected.set(
        "effects.sidecars",
        check(
            "effects.sidecars",
            "leftover_repair_temps",
            "attention",
            &[
                (
                    "counts",
                    nums(&[("leftover_repair_temps", 1), ("quarantine_sidecars", 0)]),
                ),
                ("leftover_repair_temps", list(&[effects_temp])),
                ("leftover_repair_temps_total", "1".to_owned()),
            ],
            &[finding(
                "leftover_repair_temps",
                "attention",
                Some(1),
                Some(&effects_aff),
            )],
            Some(&effects_aff),
        ),
    )?;
    assert_eq!(report.to_json(), expected.json());
    Ok(())
}

#[test]
fn quarantine_sidecar_alone_is_informational_and_healthy() -> TestResult {
    let dep = init("quarantine_only")?;
    let quarantined = hex64(b"quarantined-only");
    fs::write(
        dep.join("ledger").join(format!("{quarantined}.quarantine")),
        b"q",
    )?;
    let report = inspect_read_only("quarantine only", &dep)?;
    let mut expected = Expect::clean(&dep)?;
    expected.set(
        "ledger.sidecars",
        check(
            "ledger.sidecars",
            "quarantine_sidecars",
            "info",
            &[
                (
                    "counts",
                    nums(&[("leftover_repair_temps", 0), ("quarantine_sidecars", 1)]),
                ),
                (
                    "quarantined_digests",
                    list(&[format!("sha256:{quarantined}")]),
                ),
                ("quarantined_digests_total", "1".to_owned()),
            ],
            &[finding("quarantine_sidecars", "info", Some(1), None)],
            None,
        ),
    )?;
    assert_eq!(report.to_json(), expected.json());
    assert_eq!(report.exit_code(), 0);
    Ok(())
}

#[test]
fn import_without_manifest_batch_is_incomplete_until_the_manifest_lands() -> TestResult {
    let dep = init("imports")?;
    let ledger_path = dep.join(RELATIVE_PATH_LEDGER);
    append_batch(
        &ledger_path,
        LINEAGE,
        "batch:file-import:ab12:c0",
        "obj:import:ab12:c0",
        "sensor_capsule",
    )?;

    let report = inspect_read_only("incomplete import", &dep)?;
    let aff = obj(&[
        ("availability", s("not_yet_available")),
        ("action", s("rerun_file_import")),
        ("tracking", s("fss-2h5zq.23")),
    ]);
    let mut expected = Expect::clean(&dep)?.attention();
    expected.set(
        "imports.incomplete",
        check(
            "imports.incomplete",
            "incomplete_imports",
            "attention",
            &[
                ("counts", nums(&[("imports", 1), ("incomplete_imports", 1)])),
                ("incomplete_imports", list(&["ab12".to_owned()])),
                ("incomplete_imports_total", "1".to_owned()),
            ],
            &[finding(
                "incomplete_imports",
                "attention",
                Some(1),
                Some(&aff),
            )],
            Some(&aff),
        ),
    )?;
    assert_eq!(report.to_json(), expected.json());

    append_batch(
        &ledger_path,
        LINEAGE,
        "batch:file-import:ab12:manifest",
        "obj:import:ab12:manifest",
        FAMILY_FILE_IMPORT_MANIFEST,
    )?;
    let report = inspect_read_only("complete import", &dep)?;
    let mut expected = Expect::clean(&dep)?;
    expected.set(
        "imports.incomplete",
        check(
            "imports.incomplete",
            "clean",
            "ok",
            &[("counts", nums(&[("imports", 1), ("incomplete_imports", 0)]))],
            &[],
            None,
        ),
    )?;
    assert_eq!(report.to_json(), expected.json());
    Ok(())
}

#[test]
fn unreferenced_object_is_attention_and_not_a_deletion_instruction() -> TestResult {
    let dep = init("unreferenced")?;
    let digest = {
        let mut local = LocalRootPublisher::open(dep.join(RELATIVE_PATH_OBJECTS), small_limits())?;
        local.stage_object(b"never-published")?
    };
    let report = inspect_read_only("unreferenced", &dep)?;
    let aff = owner(
        "owner_decision",
        "no admitted root reaches these objects; this is not a deletion instruction",
    );
    let mut expected = Expect::clean(&dep)?.attention();
    expected.set(
        "objects.spool",
        check(
            "objects.spool",
            "clean",
            "ok",
            &[("counts", spool_counts(1, 0, 0))],
            &[],
            None,
        ),
    )?;
    expected.set(
        "objects.unreferenced",
        check(
            "objects.unreferenced",
            "unreferenced_objects",
            "attention",
            &[
                ("counts", nums(&[("unreferenced_objects", 1)])),
                ("unreferenced_objects", list(&[digest.to_text()])),
                ("unreferenced_objects_total", "1".to_owned()),
            ],
            &[finding(
                "unreferenced_objects",
                "attention",
                Some(1),
                Some(&aff),
            )],
            Some(&aff),
        ),
    )?;
    assert_eq!(report.to_json(), expected.json());
    Ok(())
}

#[test]
fn corrupt_and_foreign_spool_entries_are_listed() -> TestResult {
    let dep = init("corrupt_foreign_spool")?;
    let digest = {
        let mut local = LocalRootPublisher::open(dep.join(RELATIVE_PATH_OBJECTS), small_limits())?;
        local.stage_object(b"object-to-corrupt")?
    };
    let objects = dep
        .join(RELATIVE_PATH_OBJECTS)
        .join(LOCAL_SPOOL_DIR)
        .join("objects");
    let mut entries: Vec<PathBuf> = fs::read_dir(&objects)?
        .map(|entry| entry.map(|e| e.path()))
        .collect::<Result<_, _>>()?;
    entries.sort();
    let object_file = entries.first().ok_or("no staged object file")?;
    let mut bytes = fs::read(object_file)?;
    let last = bytes.last_mut().ok_or("empty object file")?;
    *last ^= 0xff;
    fs::write(object_file, &bytes)?;
    fs::write(objects.join("not-a-digest"), b"foreign")?;

    let report = inspect_read_only("corrupt and foreign spool", &dep)?;
    let corrupt_aff = owner(
        "owner_action",
        "corrupt objects are never read or admitted; restoring them is an owner decision",
    );
    let foreign_aff = owner(
        "owner_action",
        "entries outside the layout contract are never read, admitted, or deleted",
    );
    assert_eq!(
        check_json(&report, "objects.spool")?,
        check(
            "objects.spool",
            "corrupt_objects",
            "attention",
            &[
                ("corrupt_objects", list(&[digest.to_text()])),
                ("corrupt_objects_total", "1".to_owned()),
                ("counts", spool_counts(0, 1, 1)),
                (
                    "spool_foreign_entries",
                    list(&["objects/not-a-digest".to_owned()])
                ),
                ("spool_foreign_entries_total", "1".to_owned()),
            ],
            &[
                finding("corrupt_objects", "attention", Some(1), Some(&corrupt_aff)),
                finding("foreign_entries", "attention", Some(1), Some(&foreign_aff)),
            ],
            Some(&corrupt_aff),
        )
    );
    assert_eq!(report.verdict, DoctorVerdict::AttentionRequired);
    Ok(())
}

fn early_report(dep: &Path, verdict: &str, layout_check: &str) -> String {
    format!(
        "{{\"schema\":\"fss.doctor.v1\",\"version\":\"{}\",\"root\":\"{}\",\"verdict\":\"{verdict}\",\"possibly_stale\":false,\"limits\":{DEFAULT_LIMITS_JSON},\"checks\":[{layout_check}]}}",
        env!("CARGO_PKG_VERSION"),
        dep.display()
    )
}

#[test]
fn not_a_deployment_and_unknown_layout_exit_4() -> TestResult {
    let select = owner(
        "select_deployment_root",
        "pass the root of a reference deployment initialized with its LAYOUT descriptor",
    );
    let missing = |reason: &str| {
        check(
            "deployment.layout",
            "missing",
            "attention",
            &[("reason", s(reason))],
            &[finding("missing", "attention", None, Some(&select))],
            Some(&select),
        )
    };

    let empty = fresh("empty_dir")?;
    let report = inspect_read_only("empty dir", &empty)?;
    assert_eq!(
        report.to_json(),
        early_report(&empty, "not_a_deployment", &missing("missing LAYOUT file"))
    );
    assert_eq!(report.exit_code(), 4);

    let absent = empty.join("absent");
    let report = inspect_deployment(&absent);
    assert_eq!(
        report.to_json(),
        early_report(
            &absent,
            "not_a_deployment",
            &missing("target path does not exist")
        )
    );

    let file = empty.join("plain_file");
    fs::write(&file, b"not a directory")?;
    let report = inspect_deployment(&file);
    assert_eq!(
        report.to_json(),
        early_report(
            &file,
            "not_a_deployment",
            &missing("target path is not a directory")
        )
    );

    let dep = init("unknown_layout")?;
    let layout = fs::read_to_string(dep.join("LAYOUT"))?;
    let foreign = layout.replace(
        "schema=fss.reference_deployment.layout.v1",
        "schema=fss.other_layout.v9",
    );
    fs::write(dep.join("LAYOUT"), &foreign)?;
    let report = inspect_read_only("unknown layout", &dep)?;
    let unknown = check(
        "deployment.layout",
        "unknown_layout",
        "attention",
        &[
            (
                "evidence",
                obj(&[(
                    "layout_sha256",
                    s(&ContentDigest::sha256(foreign.as_bytes()).to_text()),
                )]),
            ),
            ("reason", s("incompatible layout schema")),
        ],
        &[finding("unknown_layout", "attention", None, Some(&select))],
        Some(&select),
    );
    assert_eq!(
        report.to_json(),
        early_report(&dep, "not_a_deployment", &unknown)
    );
    assert_eq!(report.exit_code(), 4);
    Ok(())
}
