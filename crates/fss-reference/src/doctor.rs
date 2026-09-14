#![forbid(unsafe_code)]
//! Read-only deployment doctor for reference deployments (fss-2h5zq.57,
//! `fss doctor --json --root <dir>`).
//!
//! [`inspect_deployment_with`] inspects a deployment root through an explicit [`DoctorIo`]
//! capability. It never writes, creates, locks, truncates, renames, fsyncs, or repairs anything
//! under the root. Listings and stats go through [`DoctorIo::fs`] ([`SpoolIo`]), and file bytes
//! through [`DoctorIo::files`] ([`JournalReadIo`]), always with a bound. Writer presence is read
//! from the host lock table through [`DoctorIo::lock_table`] and never observed by taking a lock.
//! One read-only exception is documented where it happens: the foreign-bytes repair plan digest,
//! whose canonical path and device/inode fss-ledger stats itself (see `journal_check`).
//!
//! Each journal is read once. Its length is checked against [`DoctorLimits::max_journal_bytes`]
//! before the read, and every classification of that journal (the pure journal doctor, the
//! corrupt-history scan, the semantic replay, and the repair plan digest) reuses those bytes.
//!
//! The output is SCHEMA-DOCTOR-001 (`fss.doctor.v1`, "bounded and secret-free"). Every id list
//! holds at most [`DoctorLimits::max_listed_ids`] entries (default [`MAX_LISTED_IDS`]), followed
//! by its total and, when truncated, a continuation cursor. Payload bytes are never printed; only
//! digests, counts, and offsets are.
//!
//! Unknown is never flattened. Every writer state keeps its typed name. A failed linkage replay
//! is `linkage_unknown` with its reason, and an exceeded limit is `over_budget` naming the limit.
//! A recovery command that does not exist in this build is named as a `not_yet_available`
//! affordance and never printed as a command line.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use fss_core::ContentDigest;
use fss_ledger::{
    DurableLedgerLimits, HostJournalReadIo, JournalFileMetadata, JournalReadIo, LedgerInspection,
    RepairError, inspect_durable_with_io,
};
use fss_object::{HostSpoolIo, SpoolError, SpoolIo};
use fss_publication::{
    HostLockTableSource, LocalInspection, LocalPublicationError, LockTableSource,
    WriterDetectionOptions, WriterState, detect_writers, inspect_linkage,
    inspect_with_ledger_journal,
};

use crate::DEPLOYMENT_LAYOUT_FILENAME;
use crate::ReferenceError;
use crate::durable_effect::{DurableEffectError, DurableEffectJournal, EffectJournalInspection};
use crate::reference_deployment::{
    DeploymentLayout, DeploymentLimits, find_structurally_valid_record,
};
use crate::situation_guard::EFFECT_RECONCILE_AFFORDANCE;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Schema identity of doctor output (SCHEMA-DOCTOR-001).
pub const DOCTOR_SCHEMA: &str = "fss.doctor.v1";
/// Default number of ids listed per list in one check. The remaining ids are counted and
/// resumable through the list's continuation cursor, but never printed.
pub const MAX_LISTED_IDS: usize = 32;
/// Default bound on the bytes read from the `LAYOUT` descriptor. The canonical descriptor is a
/// few hundred bytes.
pub const MAX_LAYOUT_BYTES: usize = 4096;
/// Default bound on the entries listed from one journal directory while scanning for repair
/// sidecars.
pub const MAX_SIDECAR_ENTRIES: usize = 4096;
/// Tracking bead of the explicit recovery commands (`fss-lab recover`), which do not exist in
/// this build yet.
pub const RECOVER_TRACKING_BEAD: &str = "fss-2h5zq.15";
/// Tracking bead of file import. Re-running an import completes an incomplete one.
pub const IMPORT_TRACKING_BEAD: &str = "fss-2h5zq.23";
/// Batch-id prefix of file-import batches (fss-2h5zq.23 deterministic partition:
/// `batch:file-import:<identity>:c<k>` and `batch:file-import:<identity>:manifest`).
pub const FILE_IMPORT_BATCH_PREFIX: &str = "batch:file-import:";
/// Batch-id part of the final manifest batch that completes a file import.
pub const FILE_IMPORT_MANIFEST_PART: &str = "manifest";

/// Bounds applied by one doctor run. Every bound that is hit is reported as an `over_budget`
/// status naming the limit, never as a partial or crashed check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DoctorLimits {
    /// Maximum bytes read from one journal (`ledger` or `effects`); the length is checked first.
    pub max_journal_bytes: usize,
    /// Maximum bytes read from `LAYOUT`.
    pub max_layout_bytes: usize,
    /// Maximum ids printed per list.
    pub max_listed_ids: usize,
    /// Maximum entries listed from one journal directory during the sidecar scan.
    pub max_sidecar_entries: usize,
}

impl Default for DoctorLimits {
    fn default() -> Self {
        let max_bytes = 64 * 1024 * 1024;
        Self {
            max_journal_bytes: max_bytes,
            max_layout_bytes: MAX_LAYOUT_BYTES,
            max_listed_ids: MAX_LISTED_IDS,
            max_sidecar_entries: MAX_SIDECAR_ENTRIES,
        }
    }
}

impl DoctorLimits {
    fn to_json(self) -> String {
        format!(
            "{{\"max_journal_bytes\":{},\"max_layout_bytes\":{},\"max_listed_ids\":{},\"max_sidecar_entries\":{}}}",
            self.max_journal_bytes,
            self.max_layout_bytes,
            self.max_listed_ids,
            self.max_sidecar_entries
        )
    }
}

/// Explicit I/O authority for one doctor run. Every filesystem observation made by the doctor
/// goes through one of these three capabilities, so a test can record or refuse each call. The
/// one exception is the read-only stat of a journal with foreign trailing bytes when its repair
/// plan digest is built; it is documented at its call site in `journal_check`.
#[derive(Clone, Copy)]
pub struct DoctorIo<'a> {
    /// Directory listing and metadata for the root, the layout directories, the publication root,
    /// and the journal directories. Doctor never calls its mutating or locking methods.
    pub fs: &'a dyn SpoolIo,
    /// Bounded file reads for `LAYOUT` and both journals.
    pub files: &'a dyn JournalReadIo,
    /// Host lock table used to observe writers without taking a lock.
    pub lock_table: &'a dyn LockTableSource,
}

impl DoctorIo<'static> {
    /// The host filesystem and the host lock table (`/proc/locks`).
    #[must_use]
    pub fn host() -> Self {
        Self {
            fs: &HostSpoolIo,
            files: &HostJournalReadIo,
            lock_table: &HostLockTableSource,
        }
    }
}

impl fmt::Debug for DoctorIo<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DoctorIo")
            .field("fs", &self.fs)
            .field("lock_table", &self.lock_table)
            .finish_non_exhaustive()
    }
}

/// Pure RFC 8259 string escaping helper for bounded machine JSON output.
fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                use core::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

fn json_str(s: &str) -> String {
    format!("\"{}\"", escape_json(s))
}

/// Overall verdict resulting from inspecting a deployment directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DoctorVerdict {
    /// No check reported an attention finding.
    Healthy,
    /// At least one check reported an attention finding.
    AttentionRequired,
    /// Target path is not a recognized reference deployment root.
    NotADeployment,
    /// Target path could not be accessed or read.
    Unreadable,
}

impl DoctorVerdict {
    /// Canonical string identifier for this verdict.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::AttentionRequired => "attention_required",
            Self::NotADeployment => "not_a_deployment",
            Self::Unreadable => "unreadable",
        }
    }

    /// Process exit code associated with this verdict.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Healthy => 0,
            Self::AttentionRequired => 3,
            Self::NotADeployment => 4,
            Self::Unreadable => 1,
        }
    }
}

/// Severity of a finding. Only `Attention` changes the verdict; `Info` findings, such as a live
/// writer or an in-flight tail, are reported and mark the snapshot as possibly stale.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DoctorSeverity {
    /// Nothing to report.
    Ok,
    /// Reported state that is not a fault.
    Info,
    /// A fault or an undetermined state that requires attention.
    Attention,
}

impl DoctorSeverity {
    /// Canonical string identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Info => "info",
            Self::Attention => "attention",
        }
    }
}

/// Next affordance attached to a finding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DoctorAffordance {
    /// A command that exists in this build.
    Command {
        /// Stable action name.
        action: String,
        /// Exact command line.
        command: String,
    },
    /// A recovery action whose command does not exist in this build yet. It is named, and never
    /// printed as a command line.
    NotYetAvailable {
        /// Stable action name.
        action: String,
        /// Journal or store the action targets.
        target: Option<String>,
        /// Plan digest the future apply step binds, when one could be computed.
        plan_digest: Option<String>,
        /// Bead that tracks the command.
        tracking: String,
    },
    /// An owner action or owner decision; doctor proposes no command.
    OwnerDecision {
        /// Stable action name.
        action: String,
        /// Why the decision belongs to the owner.
        detail: String,
    },
}

impl DoctorAffordance {
    fn command(action: &str, command: String) -> Self {
        Self::Command {
            action: action.to_owned(),
            command,
        }
    }

    fn not_yet(action: &str, target: Option<&str>, plan_digest: Option<String>) -> Self {
        Self::NotYetAvailable {
            action: action.to_owned(),
            target: target.map(str::to_owned),
            plan_digest,
            tracking: RECOVER_TRACKING_BEAD.to_owned(),
        }
    }

    fn owner(action: &str, detail: &str) -> Self {
        Self::OwnerDecision {
            action: action.to_owned(),
            detail: detail.to_owned(),
        }
    }

    /// Serializes this affordance to a deterministic JSON object string.
    #[must_use]
    pub fn to_json(&self) -> String {
        match self {
            Self::Command { action, command } => format!(
                "{{\"availability\":\"available\",\"action\":{},\"command\":{}}}",
                json_str(action),
                json_str(command)
            ),
            Self::NotYetAvailable {
                action,
                target,
                plan_digest,
                tracking,
            } => {
                let mut parts = vec![
                    "\"availability\":\"not_yet_available\"".to_owned(),
                    format!("\"action\":{}", json_str(action)),
                ];
                if let Some(target) = target {
                    parts.push(format!("\"target\":{}", json_str(target)));
                }
                if let Some(plan_digest) = plan_digest {
                    parts.push(format!("\"plan_digest\":{}", json_str(plan_digest)));
                }
                parts.push(format!("\"tracking\":{}", json_str(tracking)));
                format!("{{{}}}", parts.join(","))
            }
            Self::OwnerDecision { action, detail } => format!(
                "{{\"availability\":\"owner_decision\",\"action\":{},\"detail\":{}}}",
                json_str(action),
                json_str(detail)
            ),
        }
    }
}

/// One typed finding inside a check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoctorFinding {
    /// Stable finding kind; the check status is the kind of its primary finding.
    pub kind: String,
    /// Severity of the finding.
    pub severity: DoctorSeverity,
    /// Number of affected entries, where the finding is countable.
    pub count: Option<u64>,
    /// Next affordance for this finding.
    pub next_affordance: Option<DoctorAffordance>,
}

impl DoctorFinding {
    /// Serializes this finding to a deterministic JSON object string.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut parts = vec![
            format!("\"kind\":{}", json_str(&self.kind)),
            format!("\"severity\":\"{}\"", self.severity.as_str()),
        ];
        if let Some(count) = self.count {
            parts.push(format!("\"count\":{count}"));
        }
        if let Some(affordance) = &self.next_affordance {
            parts.push(format!("\"next_affordance\":{}", affordance.to_json()));
        }
        format!("{{{}}}", parts.join(","))
    }
}

/// Typed detail values attached to a [`DoctorCheck`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DoctorValue {
    /// UTF-8 string value.
    String(String),
    /// Signed integer value.
    Number(i64),
    /// Boolean flag.
    Bool(bool),
    /// Ordered, bounded list of strings.
    StringList(Vec<String>),
    /// Nested object with deterministic key order.
    Object(BTreeMap<String, DoctorValue>),
}

impl DoctorValue {
    /// Serializes this value to deterministic JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        match self {
            Self::String(s) => json_str(s),
            Self::Number(n) => n.to_string(),
            Self::Bool(b) => b.to_string(),
            Self::StringList(list) => {
                let items: Vec<String> = list.iter().map(|item| json_str(item)).collect();
                format!("[{}]", items.join(","))
            }
            Self::Object(map) => {
                let items: Vec<String> = map
                    .iter()
                    .map(|(k, v)| format!("{}:{}", json_str(k), v.to_json()))
                    .collect();
                format!("{{{}}}", items.join(","))
            }
        }
    }
}

fn num(value: usize) -> DoctorValue {
    DoctorValue::Number(i64::try_from(value).unwrap_or(i64::MAX))
}

fn num64(value: u64) -> DoctorValue {
    DoctorValue::Number(i64::try_from(value).unwrap_or(i64::MAX))
}

fn text(value: &str) -> DoctorValue {
    DoctorValue::String(value.to_owned())
}

/// Individual diagnostic check result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoctorCheck {
    /// Stable identifier of the check.
    pub id: String,
    /// Kind of the primary finding (the first finding of the highest severity), or `clean`.
    pub status: String,
    /// Highest severity among the findings.
    pub severity: DoctorSeverity,
    /// Counts (`counts`), evidence digests (`evidence`), bounded lists, and typed details.
    pub fields: BTreeMap<String, DoctorValue>,
    /// Every finding, in priority order.
    pub findings: Vec<DoctorFinding>,
    /// Next affordance of the primary finding.
    pub next_affordance: Option<DoctorAffordance>,
}

impl DoctorCheck {
    /// Constructs a clean check with the given stable ID.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            status: "clean".to_owned(),
            severity: DoctorSeverity::Ok,
            fields: BTreeMap::new(),
            findings: Vec::new(),
            next_affordance: None,
        }
    }

    fn field(&mut self, key: &str, value: DoctorValue) {
        self.fields.insert(key.to_owned(), value);
    }

    fn nested(&mut self, object: &str, key: &str, value: DoctorValue) {
        let entry = self
            .fields
            .entry(object.to_owned())
            .or_insert_with(|| DoctorValue::Object(BTreeMap::new()));
        if let DoctorValue::Object(map) = entry {
            map.insert(key.to_owned(), value);
        }
    }

    fn count(&mut self, key: &str, value: usize) {
        self.nested("counts", key, num(value));
    }

    fn count64(&mut self, key: &str, value: u64) {
        self.nested("counts", key, num64(value));
    }

    fn evidence(&mut self, key: &str, digest: ContentDigest) {
        self.nested("evidence", key, DoctorValue::String(digest.to_text()));
    }

    /// Lists at most `limit` ids of `items` (sorted), with the total and, when truncated, a
    /// continuation cursor naming the last listed id.
    fn list(&mut self, name: &str, mut items: Vec<String>, limit: usize) {
        items.sort();
        let total = items.len();
        items.truncate(limit);
        if total > items.len() {
            let mut continuation = BTreeMap::new();
            continuation.insert("omitted".to_owned(), num(total - items.len()));
            if let Some(last) = items.last() {
                continuation.insert("resume_after".to_owned(), text(last));
            }
            self.field(
                &format!("{name}_continuation"),
                DoctorValue::Object(continuation),
            );
        }
        self.field(&format!("{name}_total"), num(total));
        self.field(name, DoctorValue::StringList(items));
    }

    fn find(
        &mut self,
        kind: &str,
        severity: DoctorSeverity,
        count: Option<usize>,
        next_affordance: Option<DoctorAffordance>,
    ) {
        self.findings.push(DoctorFinding {
            kind: kind.to_owned(),
            severity,
            count: count.map(|c| u64::try_from(c).unwrap_or(u64::MAX)),
            next_affordance,
        });
    }

    fn over_budget(&mut self, limit_name: &str, limit: usize, observed: u64) {
        self.field("limit_name", text(limit_name));
        self.field("limit_bytes", num(limit));
        self.field("observed_bytes", num64(observed));
        self.find(
            "over_budget",
            DoctorSeverity::Attention,
            None,
            Some(DoctorAffordance::owner(
                "owner_action",
                "the file exceeds the doctor's read bound; it was not read and no claim is made about its contents",
            )),
        );
    }

    /// Sets the status, severity, and next affordance from the primary finding.
    #[must_use]
    fn finalized(mut self) -> Self {
        let top = self
            .findings
            .iter()
            .map(|finding| finding.severity)
            .max()
            .unwrap_or(DoctorSeverity::Ok);
        self.severity = top;
        match self.findings.iter().find(|finding| finding.severity == top) {
            Some(primary) if top != DoctorSeverity::Ok => {
                self.status.clone_from(&primary.kind);
                self.next_affordance.clone_from(&primary.next_affordance);
            }
            _ => {
                "clean".clone_into(&mut self.status);
                self.next_affordance = None;
            }
        }
        self
    }

    /// Serializes this diagnostic check to a deterministic JSON object string.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut parts = vec![
            format!("\"id\":{}", json_str(&self.id)),
            format!("\"status\":{}", json_str(&self.status)),
            format!("\"severity\":\"{}\"", self.severity.as_str()),
        ];
        for (key, value) in &self.fields {
            parts.push(format!("{}:{}", json_str(key), value.to_json()));
        }
        let findings: Vec<String> = self.findings.iter().map(DoctorFinding::to_json).collect();
        parts.push(format!("\"findings\":[{}]", findings.join(",")));
        if let Some(affordance) = &self.next_affordance {
            parts.push(format!("\"next_affordance\":{}", affordance.to_json()));
        }
        format!("{{{}}}", parts.join(","))
    }
}

/// Comprehensive report emitted by the doctor command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoctorReport {
    /// Schema URI (`fss.doctor.v1`).
    pub schema: String,
    /// Software package version.
    pub version: String,
    /// Deployment root directory inspected, if any.
    pub root: Option<PathBuf>,
    /// Summary verdict.
    pub verdict: DoctorVerdict,
    /// Whether the snapshot may already be stale: a writer or shared holder was observed, the
    /// writer state could not be determined, or it changed during the inspection.
    pub possibly_stale: bool,
    /// Bounds applied by this run.
    pub limits: DoctorLimits,
    /// Individual check results in canonical evaluation order.
    pub checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    fn early(
        root: &Path,
        limits: DoctorLimits,
        verdict: DoctorVerdict,
        check: DoctorCheck,
    ) -> Self {
        Self {
            schema: DOCTOR_SCHEMA.to_owned(),
            version: VERSION.to_owned(),
            root: Some(root.to_path_buf()),
            verdict,
            possibly_stale: false,
            limits,
            checks: vec![check.finalized()],
        }
    }

    /// Returns true if the verdict is [`DoctorVerdict::Healthy`].
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.verdict == DoctorVerdict::Healthy
    }

    /// Returns the process exit code for this report.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        self.verdict.exit_code()
    }

    /// Returns the check with the given id.
    #[must_use]
    pub fn check(&self, id: &str) -> Option<&DoctorCheck> {
        self.checks.iter().find(|check| check.id == id)
    }

    /// Serializes this report to a deterministic JSON document string.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut parts = vec![
            format!("\"schema\":{}", json_str(&self.schema)),
            format!("\"version\":{}", json_str(&self.version)),
        ];
        if let Some(root) = &self.root {
            parts.push(format!(
                "\"root\":{}",
                json_str(&root.display().to_string())
            ));
        }
        parts.push(format!("\"verdict\":\"{}\"", self.verdict.as_str()));
        parts.push(format!("\"possibly_stale\":{}", self.possibly_stale));
        parts.push(format!("\"limits\":{}", self.limits.to_json()));
        let checks: Vec<String> = self.checks.iter().map(DoctorCheck::to_json).collect();
        parts.push(format!("\"checks\":[{}]", checks.join(",")));
        format!("{{{}}}", parts.join(","))
    }
}

/// Inspects a reference deployment directory in read-only mode through the host filesystem,
/// the host lock table, and [`DoctorLimits::default`].
#[must_use]
pub fn inspect_deployment(root: &Path) -> DoctorReport {
    inspect_deployment_with(root, DoctorIo::host(), DoctorLimits::default())
}

/// Inspects a reference deployment directory in read-only mode through `io` under `limits`.
///
/// Never takes a lock, never creates, writes, truncates, renames, or removes anything, and never
/// repairs. Writers are observed twice through the lock table: before the journals are read and,
/// by the publication inspection, after them. A change between the two marks the report
/// `possibly_stale`.
#[must_use]
pub fn inspect_deployment_with(
    root: &Path,
    io: DoctorIo<'_>,
    limits: DoctorLimits,
) -> DoctorReport {
    let root_meta: io::Result<fs::Metadata> = io.fs.symlink_metadata(root);
    match root_meta {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => {
            return not_a_deployment(root, limits, "missing", "target path is not a directory");
        }
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            return unreadable(root, limits, "permission denied reading deployment root");
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return not_a_deployment(root, limits, "missing", "target path does not exist");
        }
        Err(error) => return unreadable(root, limits, &error.to_string()),
    }

    let (layout, layout_digest) = match read_layout(io, root, limits) {
        LayoutOutcome::Parsed(layout, digest) => (layout, digest),
        LayoutOutcome::Early(verdict, check) => {
            return DoctorReport::early(root, limits, verdict, check);
        }
    };

    let objects_dir = root.join(&layout.objects_relpath);
    let ledger_file = root.join(&layout.ledger_relpath);
    let effects_file = root.join(&layout.effects_relpath);
    let ledger_dir = ledger_file.parent().unwrap_or(root).to_path_buf();
    let effects_dir = effects_file.parent().unwrap_or(root).to_path_buf();

    // 1. Layout check
    let deployment_limits = DeploymentLimits::standard();
    let mut layout_check = layout_check(
        io,
        &layout,
        layout_digest,
        &deployment_limits,
        [
            ("objects", objects_dir.as_path()),
            ("ledger", ledger_dir.as_path()),
            ("effects", effects_dir.as_path()),
        ],
    );
    layout_check.field("site_lineage", text(&layout.site_lineage));

    // 2. Writer detection
    let lock_paths = vec![
        objects_dir.join(fss_publication::LOCAL_LOCK_FILE),
        objects_dir
            .join(fss_publication::LOCAL_SPOOL_DIR)
            .join(fss_object::SPOOL_LOCK_FILE),
        ledger_file.clone(),
        effects_file.clone(),
    ];
    let writer_state = detect_writers(
        io.fs,
        &lock_paths,
        Some(io.lock_table),
        WriterDetectionOptions::default(),
    );
    let writer_held = writer_state.is_held();
    let tail_may_be_in_flight = writer_held
        || matches!(
            writer_state,
            WriterState::Unknown { .. } | WriterState::InvalidLayout { .. }
        );
    let rerun = rerun_doctor(root);
    let mut writer_check = writer_check(&writer_state, &rerun);

    // 3. Ledger journal check
    let ledger_read = read_journal(io.files, &ledger_file, limits.max_journal_bytes);
    let ledger_check = journal_check(
        "ledger.journal",
        JournalKind::Ledger,
        &ledger_file,
        &ledger_read,
        tail_may_be_in_flight,
        &rerun,
    );
    let ledger_inspection =
        ledger_inspection(io, &ledger_file, &ledger_read, &layout.site_lineage, limits);

    // 4. Effects journal and obligations checks
    let effects_read = read_journal(io.files, &effects_file, limits.max_journal_bytes);
    let effects_check = journal_check(
        "effects.journal",
        JournalKind::Effects,
        &effects_file,
        &effects_read,
        tail_may_be_in_flight,
        &rerun,
    );
    let obligations_check = match effects_inspection(&effects_file, &effects_read, limits) {
        Ok(eff_report) => obligations_check(&eff_report, limits),
        Err(unavailable) => unavailable.check("effects.obligations"),
    };

    // 5. Publication checks; the publication inspection re-observes writers after the journals.
    let local_result = inspect_with_ledger_journal(
        io.fs,
        &objects_dir,
        Some(&ledger_file),
        deployment_limits.to_publication_limits(),
        Some(io.lock_table),
        WriterDetectionOptions::default(),
    );
    let (staging_check, spool_check, roots_check, unreferenced_check, tombstones_check) =
        match &local_result {
            Ok(local) => (
                staging_check(local, limits),
                spool_check(local, limits),
                roots_check(local, &ledger_inspection, limits),
                unreferenced_check(local, limits),
                tombstones_check(local, limits),
            ),
            Err(error) => {
                let unavailable = publication_unavailable(error, root);
                (
                    unavailable.check("publication.staging"),
                    unavailable.check("objects.spool"),
                    unavailable.check("publication.roots"),
                    unavailable.check("objects.unreferenced"),
                    unavailable.check("objects.tombstones"),
                )
            }
        };
    let mut possibly_stale = writer_state.possibly_stale();
    match &local_result {
        Ok(local) => {
            let after = writer_state_name(&local.writer_state);
            writer_check.field("writer_state_after", text(after));
            let changed = after != writer_state_name(&writer_state);
            if changed {
                writer_check.find(
                    "writer_state_changed",
                    DoctorSeverity::Info,
                    None,
                    Some(rerun.clone()),
                );
            }
            possibly_stale = possibly_stale || local.writer_state.possibly_stale() || changed;
        }
        Err(_) => writer_check.field("writer_state_after", text("not_probed")),
    }
    writer_check.field("possibly_stale", DoctorValue::Bool(possibly_stale));

    // 6. Import completeness
    let imports_check = imports_check(&ledger_inspection, limits);

    // 7. Repair sidecars beside each journal
    let ledger_sidecars = sidecar_check(
        "ledger.sidecars",
        JournalKind::Ledger,
        io,
        &ledger_dir,
        limits,
    );
    let effects_sidecars = sidecar_check(
        "effects.sidecars",
        JournalKind::Effects,
        io,
        &effects_dir,
        limits,
    );

    let checks = vec![
        layout_check,
        writer_check,
        ledger_check,
        effects_check,
        obligations_check,
        staging_check,
        spool_check,
        roots_check,
        unreferenced_check,
        tombstones_check,
        imports_check,
        ledger_sidecars,
        effects_sidecars,
    ];
    let checks: Vec<DoctorCheck> = checks.into_iter().map(DoctorCheck::finalized).collect();

    let verdict = if checks
        .iter()
        .any(|check| check.severity == DoctorSeverity::Attention)
    {
        DoctorVerdict::AttentionRequired
    } else {
        DoctorVerdict::Healthy
    };

    DoctorReport {
        schema: DOCTOR_SCHEMA.to_owned(),
        version: VERSION.to_owned(),
        root: Some(root.to_path_buf()),
        verdict,
        possibly_stale,
        limits,
        checks,
    }
}

fn rerun_doctor(root: &Path) -> DoctorAffordance {
    DoctorAffordance::command(
        "wait_for_writer_then_rerun_doctor",
        format!("fss doctor --json --root {}", root.display()),
    )
}

fn select_root() -> DoctorAffordance {
    DoctorAffordance::owner(
        "select_deployment_root",
        "pass the root of a reference deployment initialized with its LAYOUT descriptor",
    )
}

fn not_a_deployment(root: &Path, limits: DoctorLimits, kind: &str, reason: &str) -> DoctorReport {
    let mut check = DoctorCheck::new("deployment.layout");
    check.field("reason", text(reason));
    check.find(kind, DoctorSeverity::Attention, None, Some(select_root()));
    DoctorReport::early(root, limits, DoctorVerdict::NotADeployment, check)
}

fn unreadable(root: &Path, limits: DoctorLimits, reason: &str) -> DoctorReport {
    let mut check = DoctorCheck::new("deployment.access");
    check.field("reason", text(reason));
    check.find(
        "unreadable",
        DoctorSeverity::Attention,
        None,
        Some(DoctorAffordance::owner(
            "verify_permissions",
            "grant read access to the deployment root; doctor never changes permissions",
        )),
    );
    DoctorReport::early(root, limits, DoctorVerdict::Unreadable, check)
}

enum LayoutOutcome {
    Parsed(DeploymentLayout, ContentDigest),
    Early(DoctorVerdict, DoctorCheck),
}

/// Messages of layout parse errors that mean the descriptor is not one this build knows.
const UNKNOWN_LAYOUT_ERRORS: [&str; 4] = [
    "incompatible layout schema",
    "incompatible layout version",
    "missing layout schema",
    "missing layout version",
];

fn read_layout(io: DoctorIo<'_>, root: &Path, limits: DoctorLimits) -> LayoutOutcome {
    let path = root.join(DEPLOYMENT_LAYOUT_FILENAME);
    let mut check = DoctorCheck::new("deployment.layout");
    let early_access = |reason: String| {
        let mut access = DoctorCheck::new("deployment.access");
        access.field("reason", DoctorValue::String(reason));
        access.find(
            "unreadable",
            DoctorSeverity::Attention,
            None,
            Some(DoctorAffordance::owner(
                "verify_permissions",
                "grant read access to LAYOUT; doctor never changes permissions",
            )),
        );
        LayoutOutcome::Early(DoctorVerdict::Unreadable, access)
    };
    let meta = match io.files.symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            check.field("reason", text("missing LAYOUT file"));
            check.find(
                "missing",
                DoctorSeverity::Attention,
                None,
                Some(select_root()),
            );
            return LayoutOutcome::Early(DoctorVerdict::NotADeployment, check);
        }
        Err(error) => return early_access(error.to_string()),
    };
    if meta.is_symlink || !meta.is_file {
        check.field("reason", text("LAYOUT is not a regular file"));
        check.find(
            "missing",
            DoctorSeverity::Attention,
            None,
            Some(select_root()),
        );
        return LayoutOutcome::Early(DoctorVerdict::NotADeployment, check);
    }
    if meta.len > u64::try_from(limits.max_layout_bytes).unwrap_or(u64::MAX) {
        check.over_budget("max_layout_bytes", limits.max_layout_bytes, meta.len);
        return LayoutOutcome::Early(DoctorVerdict::AttentionRequired, check);
    }
    let bytes = match io
        .files
        .read_bounded(&path, limits.max_layout_bytes.saturating_add(1))
    {
        Ok(bytes) => bytes,
        Err(error) => return early_access(error.to_string()),
    };
    if bytes.len() > limits.max_layout_bytes {
        let observed = u64::try_from(bytes.len()).unwrap_or(u64::MAX).max(meta.len);
        check.over_budget("max_layout_bytes", limits.max_layout_bytes, observed);
        return LayoutOutcome::Early(DoctorVerdict::AttentionRequired, check);
    }
    let digest = ContentDigest::sha256(&bytes);
    check.evidence("layout_sha256", digest);
    let Ok(layout_text) = String::from_utf8(bytes) else {
        check.field("reason", text("LAYOUT is not UTF-8"));
        check.find(
            "corrupt",
            DoctorSeverity::Attention,
            None,
            Some(restore_layout()),
        );
        return LayoutOutcome::Early(DoctorVerdict::AttentionRequired, check);
    };
    match DeploymentLayout::parse_canonical_text(&layout_text) {
        Ok(layout) => LayoutOutcome::Parsed(layout, digest),
        Err(ReferenceError::InvalidSpec(reason)) if UNKNOWN_LAYOUT_ERRORS.contains(&reason) => {
            check.field("reason", text(reason));
            check.find(
                "unknown_layout",
                DoctorSeverity::Attention,
                None,
                Some(select_root()),
            );
            LayoutOutcome::Early(DoctorVerdict::NotADeployment, check)
        }
        Err(error) => {
            check.field("reason", DoctorValue::String(error.to_string()));
            check.find(
                "corrupt",
                DoctorSeverity::Attention,
                None,
                Some(restore_layout()),
            );
            LayoutOutcome::Early(DoctorVerdict::AttentionRequired, check)
        }
    }
}

fn restore_layout() -> DoctorAffordance {
    DoctorAffordance::owner(
        "restore_layout",
        "LAYOUT is not a canonical descriptor; doctor never rewrites it",
    )
}

fn layout_check(
    io: DoctorIo<'_>,
    layout: &DeploymentLayout,
    layout_digest: ContentDigest,
    deployment_limits: &DeploymentLimits,
    directories: [(&str, &Path); 3],
) -> DoctorCheck {
    let mut check = DoctorCheck::new("deployment.layout");
    check.evidence("layout_sha256", layout_digest);
    check.evidence("limits_digest", layout.limits_digest);
    check.field("format_version", num64(u64::from(layout.format_version)));
    match deployment_limits.canonical_digest() {
        Ok(digest) if digest == layout.limits_digest => {
            check.field("limits_profile", text("standard"));
        }
        _ => {
            check.field("limits_profile", text("unrecognized"));
            check.find(
                "limits_unrecognized",
                DoctorSeverity::Info,
                None,
                Some(DoctorAffordance::owner(
                    "owner_action",
                    "the LAYOUT limits digest is not the standard profile; publication was inspected under the standard limits",
                )),
            );
        }
    }
    let mut missing = Vec::new();
    let mut unreadable_dirs = Vec::new();
    for (name, path) in directories {
        let meta: io::Result<fs::Metadata> = io.fs.symlink_metadata(path);
        match meta {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => missing.push(name.to_owned()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => missing.push(name.to_owned()),
            Err(_) => unreadable_dirs.push(name.to_owned()),
        }
    }
    if !missing.is_empty() {
        let count = missing.len();
        check.list("missing_directories", missing, MAX_LISTED_IDS);
        check.find(
            "incomplete",
            DoctorSeverity::Attention,
            Some(count),
            Some(DoctorAffordance::owner(
                "restore_deployment_directories",
                "doctor never creates directories; reopening the deployment with its writer recreates them",
            )),
        );
    }
    if !unreadable_dirs.is_empty() {
        let count = unreadable_dirs.len();
        check.list("unreadable_directories", unreadable_dirs, MAX_LISTED_IDS);
        check.find(
            "unreadable",
            DoctorSeverity::Attention,
            Some(count),
            Some(DoctorAffordance::owner(
                "verify_permissions",
                "grant read access to the deployment directories",
            )),
        );
    }
    check
}

/// Stable name of a writer state; never flattened.
fn writer_state_name(state: &WriterState) -> &'static str {
    match state {
        WriterState::Held { .. } => "held",
        WriterState::SharedHolder { .. } => "shared_holder",
        WriterState::NotObserved { .. } => "not_observed",
        WriterState::NotHeld { .. } => "not_held",
        WriterState::NoLockFile { .. } => "no_lock_file",
        WriterState::InvalidLayout { .. } => "invalid_layout",
        WriterState::Unknown { .. } => "unknown",
        WriterState::NotProbed => "not_probed",
    }
}

fn writer_check(state: &WriterState, rerun: &DoctorAffordance) -> DoctorCheck {
    let mut check = DoctorCheck::new("deployment.writer");
    check.field("writer_state", text(writer_state_name(state)));
    match state {
        WriterState::Held { basis, pid_hint } | WriterState::SharedHolder { basis, pid_hint } => {
            check.field("probe_method", DoctorValue::String(basis.to_string()));
            if let Some(pid) = pid_hint {
                check.field("pid_hint", num64(u64::from(*pid)));
            }
            let kind = if state.is_held() {
                "concurrent_writer"
            } else {
                "shared_holder"
            };
            check.find(kind, DoctorSeverity::Info, None, Some(rerun.clone()));
        }
        WriterState::NotObserved { basis, scope } => {
            check.field("probe_method", text(basis));
            check.field("probe_scope", text(scope));
        }
        WriterState::NotHeld { basis } => check.field("probe_method", text(basis)),
        WriterState::NoLockFile { basis } => {
            check.field("probe_method", text(basis));
            check.find("no_lock_file", DoctorSeverity::Info, None, None);
        }
        WriterState::InvalidLayout { basis } => {
            check.field("probe_method", text(basis));
            check.find(
                "invalid_layout",
                DoctorSeverity::Attention,
                None,
                Some(DoctorAffordance::owner(
                    "inspect_lock_files",
                    "a lock path is not a regular file; writers cannot be observed until it is restored",
                )),
            );
        }
        WriterState::Unknown { reason } => {
            check.field("probe_method", text("proc_locks"));
            check.field("reason", DoctorValue::String(reason.to_string()));
            check.find(
                "unknown",
                DoctorSeverity::Attention,
                None,
                Some(DoctorAffordance::owner(
                    "restore_lock_table_access",
                    "writer presence could not be determined; the snapshot may be stale",
                )),
            );
        }
        WriterState::NotProbed => {
            check.field("probe_method", text("not_probed"));
            check.find(
                "not_probed",
                DoctorSeverity::Attention,
                None,
                Some(rerun.clone()),
            );
        }
    }
    check
}

#[derive(Clone, Copy)]
enum JournalKind {
    Ledger,
    Effects,
}

impl JournalKind {
    const fn target(self) -> &'static str {
        match self {
            Self::Ledger => "ledger",
            Self::Effects => "effects",
        }
    }

    const fn repair_action(self) -> &'static str {
        match self {
            Self::Ledger => "plan_ledger_repair_then_apply_ledger_repair",
            Self::Effects => "plan_effects_repair_then_apply_effects_repair",
        }
    }

    const fn rerun_apply_action(self) -> &'static str {
        match self {
            Self::Ledger => "rerun_apply_ledger_repair",
            Self::Effects => "rerun_apply_effects_repair",
        }
    }
}

/// One bounded read of a journal; every later classification reuses these bytes.
enum JournalRead {
    Absent,
    InvalidLayout,
    Unreadable(String),
    OverBudget { limit: usize, observed: u64 },
    Bytes(Vec<u8>),
}

fn read_journal(io: &dyn JournalReadIo, path: &Path, max_bytes: usize) -> JournalRead {
    let meta = match io.symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return JournalRead::Absent,
        Err(error) => return JournalRead::Unreadable(error.to_string()),
    };
    if meta.is_symlink || !meta.is_file {
        return JournalRead::InvalidLayout;
    }
    if meta.len > u64::try_from(max_bytes).unwrap_or(u64::MAX) {
        return JournalRead::OverBudget {
            limit: max_bytes,
            observed: meta.len,
        };
    }
    match io.read_bounded(path, max_bytes.saturating_add(1)) {
        Ok(bytes) if bytes.len() > max_bytes => JournalRead::OverBudget {
            limit: max_bytes,
            observed: u64::try_from(bytes.len()).unwrap_or(u64::MAX).max(meta.len),
        },
        Ok(bytes) => JournalRead::Bytes(bytes),
        Err(error) => JournalRead::Unreadable(error.to_string()),
    }
}

/// Serves one already-read journal snapshot to the inspection APIs, so they never re-read it.
struct SnapshotJournalIo<'a> {
    path: &'a Path,
    bytes: &'a [u8],
}

impl JournalReadIo for SnapshotJournalIo<'_> {
    fn symlink_metadata(&self, path: &Path) -> io::Result<JournalFileMetadata> {
        if path != self.path {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        }
        Ok(JournalFileMetadata {
            is_file: true,
            is_symlink: false,
            len: u64::try_from(self.bytes.len()).unwrap_or(u64::MAX),
        })
    }

    fn read_bounded(&self, path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
        if path != self.path {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        }
        let end = self.bytes.len().min(max_bytes);
        Ok(self.bytes.get(..end).unwrap_or_default().to_vec())
    }
}

fn journal_check(
    id: &str,
    kind: JournalKind,
    path: &Path,
    read: &JournalRead,
    tail_may_be_in_flight: bool,
    rerun: &DoctorAffordance,
) -> DoctorCheck {
    let mut check = DoctorCheck::new(id);
    let bytes = match read {
        JournalRead::Absent => {
            check.find(
                "absent",
                DoctorSeverity::Attention,
                None,
                Some(DoctorAffordance::owner(
                    "restore_journal",
                    "the deployment journal is missing; doctor never creates it",
                )),
            );
            return check;
        }
        JournalRead::InvalidLayout => {
            check.find(
                "invalid_layout",
                DoctorSeverity::Attention,
                None,
                Some(DoctorAffordance::owner(
                    "inspect_journal_path",
                    "the journal path is a symlink or not a regular file",
                )),
            );
            return check;
        }
        JournalRead::Unreadable(reason) => {
            check.field("reason", text(reason));
            check.find(
                "unreadable",
                DoctorSeverity::Attention,
                None,
                Some(DoctorAffordance::owner(
                    "verify_permissions",
                    "grant read access to the journal",
                )),
            );
            return check;
        }
        JournalRead::OverBudget { limit, observed } => {
            check.over_budget("max_journal_bytes", *limit, *observed);
            return check;
        }
        JournalRead::Bytes(bytes) => bytes,
    };
    check.count("file_len", bytes.len());
    check.evidence("journal_sha256", ContentDigest::sha256(bytes));
    let report = match fss_ledger::doctor(bytes) {
        Ok(report) => report,
        Err(RepairError::OverBudget { limit, actual }) => {
            check.over_budget(
                "max_journal_bytes",
                limit,
                u64::try_from(actual).unwrap_or(u64::MAX),
            );
            return check;
        }
        Err(error) => {
            check.field("reason", DoctorValue::String(error.to_string()));
            check.find(
                "corrupt",
                DoctorSeverity::Attention,
                None,
                Some(DoctorAffordance::owner(
                    "owner_action",
                    "the journal could not be classified; inspect it before any repair",
                )),
            );
            return check;
        }
    };
    check.count64("committed_len", report.committed_len());
    check.count("records_count", report.records_count());
    check.evidence("last_root", report.last_root());
    if let Some(foreign) = report.foreign_range() {
        check.field("foreign_offset", num64(foreign.offset()));
        check.field("foreign_length", num64(foreign.length()));
        check.evidence("foreign_digest", foreign.digest());
        if let Some(offset) =
            find_structurally_valid_record(bytes, foreign.offset(), foreign.length())
        {
            check.field("valid_record_offset", num64(offset));
            check.find(
                "corrupt_history",
                DoctorSeverity::Attention,
                None,
                Some(DoctorAffordance::owner(
                    "owner_action",
                    "a structurally valid record lies inside the foreign range; foreign-byte repair must not be applied",
                )),
            );
        } else {
            // Seam exception, read-only: this is the one filesystem access the doctor makes
            // outside `DoctorIo`. The plan digest binds the journal's canonical path, device and
            // inode, and fss-ledger computes them itself: `RepairDoctorReport::plan` reaches
            // `SealedRepairPlan::create_with_cut` (crates/fss-ledger/src/repair.rs), which calls
            // `fs::canonicalize(path)` and then `fs::metadata` on the result. Neither call opens,
            // creates, locks or modifies anything. fss-ledger has no plan constructor that accepts
            // a caller-supplied canonical path and device/inode, and its digest function is
            // private, so routing these stats through `DoctorIo::fs` needs an fss-ledger API
            // change. The contract test
            // `foreign_bytes_plan_digest_is_the_only_off_seam_read_and_changes_nothing` proves the
            // root stays byte- and mtime-identical.
            let plan_digest = match report.plan(path) {
                Ok(plan) => Some(plan.plan_digest().to_string()),
                Err(error) => {
                    check.field(
                        "plan_unavailable_reason",
                        DoctorValue::String(error.to_string()),
                    );
                    None
                }
            };
            if let Some(plan_digest) = &plan_digest {
                check.field("plan_digest", text(plan_digest));
            }
            let unavailable = plan_digest.is_none();
            check.find(
                "foreign_trailing_bytes",
                DoctorSeverity::Attention,
                None,
                Some(DoctorAffordance::not_yet(
                    kind.repair_action(),
                    Some(kind.target()),
                    plan_digest,
                )),
            );
            if unavailable {
                check.find("plan_unavailable", DoctorSeverity::Attention, None, None);
            }
        }
    } else if let Some(offset) = report.incomplete_tail() {
        check.field("incomplete_tail_offset", num64(offset));
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        check.count64("incomplete_tail_bytes", len.saturating_sub(offset));
        if tail_may_be_in_flight {
            check.find(
                "possibly_in_flight",
                DoctorSeverity::Info,
                None,
                Some(rerun.clone()),
            );
        } else {
            check.find(
                "incomplete_tail",
                DoctorSeverity::Attention,
                None,
                Some(DoctorAffordance::not_yet(
                    "truncate_incomplete_tail",
                    Some(kind.target()),
                    None,
                )),
            );
        }
    }
    check
}

fn ledger_inspection(
    io: DoctorIo<'_>,
    path: &Path,
    read: &JournalRead,
    site_lineage: &str,
    limits: DoctorLimits,
) -> Result<LedgerInspection, String> {
    let bound = DurableLedgerLimits::from(limits.max_journal_bytes);
    match read {
        JournalRead::Bytes(bytes) => {
            let snapshot = SnapshotJournalIo { path, bytes };
            inspect_durable_with_io(&snapshot, path, site_lineage, bound)
                .map_err(|error| format!("ledger replay failed: {error}"))
        }
        JournalRead::Absent => inspect_durable_with_io(io.files, path, site_lineage, bound)
            .map_err(|error| format!("ledger replay failed: {error}")),
        JournalRead::InvalidLayout => {
            Err("ledger journal path is a symlink or not a regular file".to_owned())
        }
        JournalRead::Unreadable(reason) => Err(format!("ledger journal unreadable: {reason}")),
        JournalRead::OverBudget { limit, observed } => Err(format!(
            "ledger journal exceeds max_journal_bytes ({observed} > {limit} bytes)"
        )),
    }
}

/// Why a check could not be computed: an exceeded limit or an undetermined state.
struct Unavailable {
    over_budget: Option<(String, usize, u64)>,
    reason: String,
}

impl Unavailable {
    fn check(&self, id: &str) -> DoctorCheck {
        let mut check = DoctorCheck::new(id);
        check.field("reason", text(&self.reason));
        if let Some((limit_name, limit, observed)) = &self.over_budget {
            check.over_budget(limit_name, *limit, *observed);
        } else {
            check.find(
                "unknown",
                DoctorSeverity::Attention,
                None,
                Some(DoctorAffordance::owner(
                    "owner_action",
                    "this state could not be determined; it is reported as unknown, never as clean",
                )),
            );
        }
        check
    }
}

fn effects_inspection(
    path: &Path,
    read: &JournalRead,
    limits: DoctorLimits,
) -> Result<EffectJournalInspection, Unavailable> {
    let unknown = |reason: String| Unavailable {
        over_budget: None,
        reason,
    };
    match read {
        JournalRead::Bytes(bytes) => {
            let snapshot = SnapshotJournalIo { path, bytes };
            match DurableEffectJournal::inspect_with_io(
                &snapshot,
                path,
                DurableLedgerLimits::from(limits.max_journal_bytes),
            ) {
                Ok(inspection) => Ok(inspection),
                Err(DurableEffectError::OverBudget { limit, actual }) => Err(Unavailable {
                    over_budget: Some((
                        "max_journal_bytes".to_owned(),
                        limit,
                        u64::try_from(actual).unwrap_or(u64::MAX),
                    )),
                    reason: "effects journal exceeds max_journal_bytes".to_owned(),
                }),
                Err(error) => Err(unknown(format!("effects journal replay failed: {error}"))),
            }
        }
        JournalRead::Absent => Err(unknown("effects journal absent".to_owned())),
        JournalRead::InvalidLayout => Err(unknown(
            "effects journal path is a symlink or not a regular file".to_owned(),
        )),
        JournalRead::Unreadable(reason) => {
            Err(unknown(format!("effects journal unreadable: {reason}")))
        }
        JournalRead::OverBudget { limit, observed } => Err(Unavailable {
            over_budget: Some(("max_journal_bytes".to_owned(), *limit, *observed)),
            reason: "effects journal exceeds max_journal_bytes".to_owned(),
        }),
    }
}

fn obligations_check(eff_report: &EffectJournalInspection, limits: DoctorLimits) -> DoctorCheck {
    let mut check = DoctorCheck::new("effects.obligations");
    let counts = &eff_report.obligation_counts;
    check.count("total", counts.total);
    check.count("pending", counts.pending);
    check.count("verified", counts.verified);
    check.count("failed", counts.failed);
    check.count("cancelled", counts.cancelled);
    check.count("indeterminate", counts.indeterminate);
    check.count("terminal", counts.terminal());
    check.count(
        "indeterminate_operations",
        eff_report.indeterminate_operations.len(),
    );
    if !eff_report.indeterminate_operations.is_empty() {
        let ids: Vec<String> = eff_report
            .indeterminate_operations
            .iter()
            .map(|op| op.operation_id.to_string())
            .collect();
        let count = ids.len();
        check.list("indeterminate_operations", ids, limits.max_listed_ids);
        check.field("reconcile_affordance", text(EFFECT_RECONCILE_AFFORDANCE));
        check.find(
            "indeterminate_obligations",
            DoctorSeverity::Attention,
            Some(count),
            Some(DoctorAffordance::not_yet(
                "reconcile_effects",
                Some("effects"),
                None,
            )),
        );
    }
    if counts.pending > 0 {
        check.find(
            "pending_obligations",
            DoctorSeverity::Info,
            Some(counts.pending),
            None,
        );
    }
    check
}

fn publication_unavailable(error: &LocalPublicationError, root: &Path) -> Unavailable {
    let relative = |directory: &Path| {
        directory
            .strip_prefix(root)
            .unwrap_or(directory)
            .display()
            .to_string()
    };
    match error {
        LocalPublicationError::EntryLimit {
            directory,
            maximum,
            at_least,
        } => Unavailable {
            over_budget: Some((
                "directory_entry_limit".to_owned(),
                *maximum,
                u64::try_from(*at_least).unwrap_or(u64::MAX),
            )),
            reason: format!("directory {} exceeds its entry bound", relative(directory)),
        },
        LocalPublicationError::Spool(SpoolError::EntryLimit { directory, maximum }) => {
            Unavailable {
                over_budget: Some((
                    "directory_entry_limit".to_owned(),
                    *maximum,
                    u64::try_from(maximum.saturating_add(1)).unwrap_or(u64::MAX),
                )),
                reason: format!("directory {} exceeds its entry bound", relative(directory)),
            }
        }
        other => Unavailable {
            over_budget: None,
            reason: format!("publication inspection failed: {other}"),
        },
    }
}

fn staging_check(local: &LocalInspection, limits: DoctorLimits) -> DoctorCheck {
    let mut check = DoctorCheck::new("publication.staging");
    let orphaned = &local.report.spool.orphaned_staging;
    check.count("orphaned_staging", orphaned.len());
    check.count64(
        "orphaned_staging_bytes",
        orphaned
            .iter()
            .fold(0_u64, |sum, entry| sum.saturating_add(entry.bytes)),
    );
    if !local.report.spool.orphaned_staging.is_empty() {
        let paths: Vec<String> = orphaned
            .iter()
            .map(|entry| entry.path.display().to_string())
            .collect();
        let count = paths.len();
        check.list("orphaned_staging", paths, limits.max_listed_ids);
        check.find(
            "orphaned_staging",
            DoctorSeverity::Attention,
            Some(count),
            Some(DoctorAffordance::not_yet(
                "discard_orphaned_staging",
                Some("objects"),
                None,
            )),
        );
    }
    check
}

fn spool_check(local: &LocalInspection, limits: DoctorLimits) -> DoctorCheck {
    let mut check = DoctorCheck::new("objects.spool");
    let spool = &local.report.spool;
    check.count("admitted", spool.admitted.len());
    check.count("corrupt_objects", spool.corrupt.len());
    check.count("spool_foreign_entries", spool.foreign.len());
    check.count("publication_foreign_entries", local.report.foreign.len());
    if !spool.corrupt.is_empty() {
        let digests: Vec<String> = spool.corrupt.iter().map(|c| c.digest.to_text()).collect();
        let count = digests.len();
        check.list("corrupt_objects", digests, limits.max_listed_ids);
        check.find(
            "corrupt_objects",
            DoctorSeverity::Attention,
            Some(count),
            Some(DoctorAffordance::owner(
                "owner_action",
                "corrupt objects are never read or admitted; restoring them is an owner decision",
            )),
        );
    }
    let foreign_count = spool.foreign.len() + local.report.foreign.len();
    if foreign_count > 0 {
        if !spool.foreign.is_empty() {
            let paths: Vec<String> = spool
                .foreign
                .iter()
                .map(|entry| entry.path.display().to_string())
                .collect();
            check.list("spool_foreign_entries", paths, limits.max_listed_ids);
        }
        if !local.report.foreign.is_empty() {
            let paths: Vec<String> = local
                .report
                .foreign
                .iter()
                .map(|path| path.display().to_string())
                .collect();
            check.list("publication_foreign_entries", paths, limits.max_listed_ids);
        }
        check.find(
            "foreign_entries",
            DoctorSeverity::Attention,
            Some(foreign_count),
            Some(DoctorAffordance::owner(
                "owner_action",
                "entries outside the layout contract are never read, admitted, or deleted",
            )),
        );
    }
    if local.spool_over_capacity {
        check.field("limit_name", text("spool_capacity"));
        check.find(
            "over_budget",
            DoctorSeverity::Attention,
            None,
            Some(DoctorAffordance::owner(
                "owner_action",
                "the recovered spool index exceeds its object or byte bound; open would refuse it",
            )),
        );
    }
    if local.missing_layout {
        check.find(
            "missing_layout",
            DoctorSeverity::Attention,
            None,
            Some(DoctorAffordance::owner(
                "restore_deployment_directories",
                "a publication or spool directory is missing; doctor never creates it",
            )),
        );
    }
    if local.holds_migration_pending {
        check.find("holds_migration_pending", DoctorSeverity::Info, None, None);
    }
    check
}

fn roots_check(
    local: &LocalInspection,
    ledger: &Result<LedgerInspection, String>,
    limits: DoctorLimits,
) -> DoctorCheck {
    let mut check = DoctorCheck::new("publication.roots");
    check.count("visible_roots", local.report.roots.len());
    check.count("broken_roots", local.broken_slots.len());
    if !local.broken_slots.is_empty() {
        let slots: Vec<String> = local
            .broken_slots
            .iter()
            .map(|slot| slot.as_str().to_owned())
            .collect();
        let count = slots.len();
        check.list("broken_slots", slots, limits.max_listed_ids);
        check.find(
            "broken_roots",
            DoctorSeverity::Attention,
            Some(count),
            Some(DoctorAffordance::owner(
                "owner_action",
                "broken root records are never admitted; inspecting or restoring them is an owner decision",
            )),
        );
    }
    let linkage = match ledger {
        Err(reason) => {
            check.field("linkage_state", text("unknown"));
            check.field("linkage_reason", text(reason));
            check.find(
                "linkage_unknown",
                DoctorSeverity::Attention,
                None,
                Some(DoctorAffordance::owner(
                    "owner_action",
                    "root-ledger linkage could not be determined; pending roots, unbacked claims, and slot conflicts are unknown",
                )),
            );
            None
        }
        Ok(inspection) => {
            check.field("linkage_state", text("inspected"));
            Some(inspect_linkage(local, inspection))
        }
    };
    if let Some(linkage) = &linkage {
        check.count("ledgered_roots", linkage.ledgered.len());
        check.count("pending_roots", linkage.pending.len());
        check.count("unbacked_claims", linkage.unbacked_ledger_claims.len());
        check.count("slot_conflicts", linkage.conflicts.len());
        check.count("unledgerable_roots", linkage.unledgerable.len());
        check.count("not_durable_roots", linkage.not_durable.len());
        if !linkage.conflicts.is_empty() {
            let slots: Vec<String> = linkage
                .conflicts
                .iter()
                .map(|conflict| conflict.slot.as_str().to_owned())
                .collect();
            let count = slots.len();
            check.list("slot_conflicts", slots, limits.max_listed_ids);
            check.find(
                "slot_conflicts",
                DoctorSeverity::Attention,
                Some(count),
                Some(DoctorAffordance::owner(
                    "owner_action",
                    "the ledger assigns these slots to a different root; resolving the conflict is an owner decision",
                )),
            );
        }
        if !linkage.unbacked_ledger_claims.is_empty() {
            let ids: Vec<String> = linkage
                .unbacked_ledger_claims
                .iter()
                .map(|claim| claim.object_id.as_str().to_owned())
                .collect();
            let count = ids.len();
            check.list("unbacked_claims", ids, limits.max_listed_ids);
            check.find(
                "unbacked_claims",
                DoctorSeverity::Attention,
                Some(count),
                Some(DoctorAffordance::owner(
                    "owner_action",
                    "no durable root backs these ledger claims; restoring the root or superseding the claim is an owner decision",
                )),
            );
        }
    }
    let temps: BTreeSet<String> = local
        .report
        .orphaned_temps
        .iter()
        .chain(local.redundant_temps.iter())
        .map(|path| path.display().to_string())
        .collect();
    check.count("orphaned_root_temps", temps.len());
    if !temps.is_empty() {
        let count = temps.len();
        check.list(
            "orphaned_root_temps",
            temps.into_iter().collect(),
            limits.max_listed_ids,
        );
        check.find(
            "orphaned_root_temps",
            DoctorSeverity::Attention,
            Some(count),
            Some(DoctorAffordance::not_yet(
                "discard_orphaned_temps",
                Some("objects"),
                None,
            )),
        );
    }
    if let Some(linkage) = &linkage {
        if !linkage.pending.is_empty() {
            let slots: Vec<String> = linkage
                .pending
                .iter()
                .map(|pending| pending.slot.as_str().to_owned())
                .collect();
            let count = slots.len();
            check.list("pending_slots", slots, limits.max_listed_ids);
            check.find(
                "pending_roots",
                DoctorSeverity::Attention,
                Some(count),
                Some(DoctorAffordance::owner(
                    "rerun_producing_command",
                    "rerun the command that produced the root; an explicit ledger commit is an owner decision",
                )),
            );
        }
        if !linkage.unledgerable.is_empty() {
            let slots: Vec<String> = linkage
                .unledgerable
                .iter()
                .map(|slot| slot.as_str().to_owned())
                .collect();
            let count = slots.len();
            check.list("unledgerable_slots", slots, limits.max_listed_ids);
            check.find(
                "unledgerable_roots",
                DoctorSeverity::Attention,
                Some(count),
                Some(DoctorAffordance::owner(
                    "owner_action",
                    "these slots have no ledger identity; renaming or retiring them is an owner decision",
                )),
            );
        }
        if !linkage.not_durable.is_empty() {
            let slots: Vec<String> = linkage
                .not_durable
                .iter()
                .map(|slot| slot.as_str().to_owned())
                .collect();
            let count = slots.len();
            check.list("not_durable_slots", slots, limits.max_listed_ids);
            check.find("not_durable_roots", DoctorSeverity::Info, Some(count), None);
        }
    }
    check
}

fn unreferenced_check(local: &LocalInspection, limits: DoctorLimits) -> DoctorCheck {
    let mut check = DoctorCheck::new("objects.unreferenced");
    let unreferenced = &local.report.unreferenced_objects;
    check.count("unreferenced_objects", unreferenced.len());
    if !unreferenced.is_empty() {
        let digests: Vec<String> = unreferenced.iter().map(|d| d.to_text()).collect();
        let count = digests.len();
        check.list("unreferenced_objects", digests, limits.max_listed_ids);
        check.find(
            "unreferenced_objects",
            DoctorSeverity::Attention,
            Some(count),
            Some(DoctorAffordance::owner(
                "owner_decision",
                "no admitted root reaches these objects; this is not a deletion instruction",
            )),
        );
    }
    check
}

fn tombstones_check(local: &LocalInspection, limits: DoctorLimits) -> DoctorCheck {
    let mut check = DoctorCheck::new("objects.tombstones");
    let tombstones = &local.report.tombstones;
    check.count("tombstones", tombstones.len());
    if !tombstones.is_empty() {
        let digests: Vec<String> = tombstones.iter().map(|d| d.to_text()).collect();
        let count = digests.len();
        check.list("tombstones", digests, limits.max_listed_ids);
        check.find("tombstones", DoctorSeverity::Info, Some(count), None);
    }
    check
}

fn imports_check(ledger: &Result<LedgerInspection, String>, limits: DoctorLimits) -> DoctorCheck {
    let mut check = DoctorCheck::new("imports.incomplete");
    let inspection = match ledger {
        Ok(inspection) => inspection,
        Err(reason) => {
            check.field("reason", text(reason));
            check.find(
                "unknown",
                DoctorSeverity::Attention,
                None,
                Some(DoctorAffordance::owner(
                    "owner_action",
                    "the ledger could not be replayed; import completeness is unknown",
                )),
            );
            return check;
        }
    };
    // identity -> (capsule batches, manifest batch present)
    let mut imports: BTreeMap<&str, (usize, bool)> = BTreeMap::new();
    for batch in &inspection.batches {
        let Some(rest) = batch
            .batch_id
            .as_str()
            .strip_prefix(FILE_IMPORT_BATCH_PREFIX)
        else {
            continue;
        };
        let Some((identity, part)) = rest.rsplit_once(':') else {
            continue;
        };
        let entry = imports.entry(identity).or_default();
        if part == FILE_IMPORT_MANIFEST_PART {
            entry.1 = true;
        } else if part
            .strip_prefix('c')
            .is_some_and(|k| !k.is_empty() && k.bytes().all(|b| b.is_ascii_digit()))
        {
            entry.0 += 1;
        }
    }
    let incomplete: Vec<String> = imports
        .iter()
        .filter(|(_, (capsules, manifest))| *capsules > 0 && !*manifest)
        .map(|(identity, _)| (*identity).to_owned())
        .collect();
    check.count("imports", imports.len());
    check.count("incomplete_imports", incomplete.len());
    if !incomplete.is_empty() {
        let count = incomplete.len();
        check.list("incomplete_imports", incomplete, limits.max_listed_ids);
        check.find(
            "incomplete_imports",
            DoctorSeverity::Attention,
            Some(count),
            Some(DoctorAffordance::NotYetAvailable {
                action: "rerun_file_import".to_owned(),
                target: None,
                plan_digest: None,
                tracking: IMPORT_TRACKING_BEAD.to_owned(),
            }),
        );
    }
    check
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Lists `<digest-hex>.quarantine` sidecars (informational) and `<digest-hex>.tmp.<pid>.<n>`
/// leftovers of an interrupted repair apply (attention) in one journal directory.
fn sidecar_check(
    id: &str,
    kind: JournalKind,
    io: DoctorIo<'_>,
    directory: &Path,
    limits: DoctorLimits,
) -> DoctorCheck {
    let mut check = DoctorCheck::new(id);
    let unreadable = |check: &mut DoctorCheck, reason: String| {
        check.field("reason", DoctorValue::String(reason));
        check.find(
            "unreadable",
            DoctorSeverity::Attention,
            None,
            Some(DoctorAffordance::owner(
                "verify_permissions",
                "grant read access to the journal directory",
            )),
        );
    };
    let mut entries = match io.fs.read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            check.find(
                "absent",
                DoctorSeverity::Attention,
                None,
                Some(DoctorAffordance::owner(
                    "restore_deployment_directories",
                    "the journal directory is missing; doctor never creates it",
                )),
            );
            return check;
        }
        Err(error) => {
            unreadable(&mut check, error.to_string());
            return check;
        }
    };
    let mut quarantined = Vec::new();
    let mut leftovers = Vec::new();
    let mut scanned = 0_usize;
    while let Some(entry) = io.fs.next_dir_entry(&mut entries) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                unreadable(&mut check, error.to_string());
                return check;
            }
        };
        scanned += 1;
        if scanned > limits.max_sidecar_entries {
            check.field("limit_name", text("max_sidecar_entries"));
            check.field("limit_entries", num(limits.max_sidecar_entries));
            check.field("observed_entries_at_least", num(scanned));
            check.find(
                "over_budget",
                DoctorSeverity::Attention,
                None,
                Some(DoctorAffordance::owner(
                    "owner_action",
                    "the journal directory holds more entries than the sidecar scan bound",
                )),
            );
            return check;
        }
        let file_type: fs::FileType = match io.fs.entry_file_type(&entry) {
            Ok(file_type) => file_type,
            Err(error) => {
                unreadable(&mut check, error.to_string());
                return check;
            }
        };
        if !file_type.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if let Some(hex) = name.strip_suffix(".quarantine") {
            if is_hex64(hex) {
                quarantined.push(format!("sha256:{hex}"));
            }
        } else if let Some((hex, attempt)) = name.split_once(".tmp.") {
            let attempt_ok = attempt
                .split_once('.')
                .is_some_and(|(pid, n)| is_digits(pid) && is_digits(n));
            if is_hex64(hex) && attempt_ok {
                leftovers.push(name.to_owned());
            }
        }
    }
    check.count("quarantine_sidecars", quarantined.len());
    check.count("leftover_repair_temps", leftovers.len());
    if !leftovers.is_empty() {
        let count = leftovers.len();
        check.list("leftover_repair_temps", leftovers, limits.max_listed_ids);
        check.find(
            "leftover_repair_temps",
            DoctorSeverity::Attention,
            Some(count),
            Some(DoctorAffordance::not_yet(
                kind.rerun_apply_action(),
                Some(kind.target()),
                None,
            )),
        );
    }
    if !quarantined.is_empty() {
        let count = quarantined.len();
        check.list("quarantined_digests", quarantined, limits.max_listed_ids);
        check.find(
            "quarantine_sidecars",
            DoctorSeverity::Info,
            Some(count),
            None,
        );
    }
    check
}

#[cfg(test)]
mod tests {
    use super::{DoctorCheck, DoctorLimits, DoctorSeverity, DoctorValue, MAX_LISTED_IDS};
    use fss_ledger::DurableLedgerLimits;

    #[test]
    fn default_journal_bound_matches_the_durable_inspection_default() {
        assert_eq!(
            DoctorLimits::default().max_journal_bytes,
            DurableLedgerLimits::DEFAULT_MAX_JOURNAL_BYTES
        );
        assert_eq!(DoctorLimits::default().max_listed_ids, MAX_LISTED_IDS);
    }

    #[test]
    fn list_is_bounded_with_total_and_continuation() {
        let mut check = DoctorCheck::new("x");
        let ids: Vec<String> = (0..5).map(|i| format!("id:{i}")).collect();
        check.list("ids", ids, 2);
        assert_eq!(
            check.fields.get("ids"),
            Some(&DoctorValue::StringList(vec![
                "id:0".to_owned(),
                "id:1".to_owned()
            ]))
        );
        assert_eq!(check.fields.get("ids_total"), Some(&DoctorValue::Number(5)));
        assert_eq!(
            check.to_json(),
            "{\"id\":\"x\",\"status\":\"clean\",\"severity\":\"ok\",\"ids\":[\"id:0\",\"id:1\"],\"ids_continuation\":{\"omitted\":3,\"resume_after\":\"id:1\"},\"ids_total\":5,\"findings\":[]}"
        );
    }

    #[test]
    fn primary_finding_is_first_of_highest_severity() {
        let mut check = DoctorCheck::new("x");
        check.find("a", DoctorSeverity::Info, None, None);
        check.find("b", DoctorSeverity::Attention, Some(2), None);
        check.find("c", DoctorSeverity::Attention, None, None);
        let check = check.finalized();
        assert_eq!(check.status, "b");
        assert_eq!(check.severity, DoctorSeverity::Attention);
        let info_only = {
            let mut c = DoctorCheck::new("y");
            c.find("live", DoctorSeverity::Info, None, None);
            c.finalized()
        };
        assert_eq!(info_only.status, "live");
        assert_eq!(info_only.severity, DoctorSeverity::Info);
    }
}
