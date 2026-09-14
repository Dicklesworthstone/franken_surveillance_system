#![forbid(unsafe_code)]
//! Read-only deployment diagnostic doctor for reference deployments.
//!
//! Inspects real reference deployments on disk without taking writer locks,
//! without modifying files, and without performing repair.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use fss_ledger::{DurableLedgerLimits, doctor_bounded};
use fss_object::HostSpoolIo;
use fss_publication::{
    HostLockTableSource, LocalPublicationLimits, WriterDetectionOptions, WriterState,
    detect_writers, inspect_linkage, inspect_with_ledger_journal,
};

use crate::DEPLOYMENT_LAYOUT_FILENAME;
use crate::durable_effect::DurableEffectJournal;
use crate::reference_deployment::{
    DeploymentLayout, DeploymentLimits, find_structurally_valid_record,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

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

/// Overall verdict resulting from inspecting a deployment directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DoctorVerdict {
    /// Deployment is fully consistent, quiescent, and intact.
    Healthy,
    /// Deployment requires attention or recovery actions.
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

/// Typed detail values attached to a [`DoctorCheck`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DoctorValue {
    /// UTF-8 string value.
    String(String),
    /// Signed integer value.
    Number(i64),
    /// Boolean flag.
    Bool(bool),
    /// Ordered list of strings.
    StringList(Vec<String>),
}

/// Individual diagnostic check result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoctorCheck {
    /// Stable identifier of the check.
    pub id: String,
    /// Machine status string of this check (e.g. "clean", "concurrent_writer", etc.).
    pub status: String,
    /// Human-readable explanation.
    pub message: Option<String>,
    /// Concrete next affordance command or owner action guidance.
    pub next_affordance: Option<String>,
    /// Structured key-value details.
    pub fields: BTreeMap<String, DoctorValue>,
}

impl DoctorCheck {
    /// Constructs a new check with the given stable ID and status.
    #[must_use]
    pub fn new(id: impl Into<String>, status: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            status: status.into(),
            message: None,
            next_affordance: None,
            fields: BTreeMap::new(),
        }
    }

    /// Serializes this diagnostic check to a deterministic JSON object string.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut parts = Vec::new();
        parts.push(format!("\"id\":\"{}\"", escape_json(&self.id)));
        parts.push(format!("\"status\":\"{}\"", escape_json(&self.status)));
        if let Some(msg) = &self.message {
            parts.push(format!("\"message\":\"{}\"", escape_json(msg)));
        }
        for (k, v) in &self.fields {
            match v {
                DoctorValue::String(s) => {
                    parts.push(format!("\"{}\":\"{}\"", escape_json(k), escape_json(s)));
                }
                DoctorValue::Number(n) => {
                    parts.push(format!("\"{}\":{}", escape_json(k), n));
                }
                DoctorValue::Bool(b) => {
                    parts.push(format!("\"{}\":{}", escape_json(k), b));
                }
                DoctorValue::StringList(list) => {
                    let items: Vec<String> = list
                        .iter()
                        .map(|item| format!("\"{}\"", escape_json(item)))
                        .collect();
                    parts.push(format!("\"{}\":[{}]", escape_json(k), items.join(",")));
                }
            }
        }
        if let Some(aff) = &self.next_affordance {
            parts.push(format!("\"next_affordance\":\"{}\"", escape_json(aff)));
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
    /// Individual check results in canonical evaluation order.
    pub checks: Vec<DoctorCheck>,
}

impl DoctorReport {
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

    /// Serializes this report to a deterministic JSON document string.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut parts = Vec::new();
        parts.push(format!("\"schema\":\"{}\"", escape_json(&self.schema)));
        parts.push(format!("\"version\":\"{}\"", escape_json(&self.version)));
        if let Some(root) = &self.root {
            parts.push(format!(
                "\"root\":\"{}\"",
                escape_json(&root.display().to_string())
            ));
        }
        parts.push(format!("\"verdict\":\"{}\"", self.verdict.as_str()));
        let check_strs: Vec<String> = self.checks.iter().map(DoctorCheck::to_json).collect();
        parts.push(format!("\"checks\":[{}]", check_strs.join(",")));
        format!("{{{}}}", parts.join(","))
    }
}

/// Inspects a reference deployment directory in pure read-only mode.
///
/// Never takes exclusive writer locks, never creates temporary files,
/// never truncates journals, and never modifies filesystem state.
#[must_use]
pub fn inspect_deployment(root: &Path) -> DoctorReport {
    let root_meta = match fs::symlink_metadata(root) {
        Ok(m) => m,
        Err(e) => {
            if e.kind() == io::ErrorKind::PermissionDenied {
                return DoctorReport {
                    schema: "fss.doctor.v1".to_owned(),
                    version: VERSION.to_owned(),
                    root: Some(root.to_path_buf()),
                    verdict: DoctorVerdict::Unreadable,
                    checks: vec![DoctorCheck {
                        id: "deployment.access".to_owned(),
                        status: "unreadable".to_owned(),
                        message: Some("permission denied reading deployment root".to_owned()),
                        next_affordance: Some(
                            "verify filesystem permissions for deployment root".to_owned(),
                        ),
                        fields: BTreeMap::new(),
                    }],
                };
            }
            return DoctorReport {
                schema: "fss.doctor.v1".to_owned(),
                version: VERSION.to_owned(),
                root: Some(root.to_path_buf()),
                verdict: DoctorVerdict::NotADeployment,
                checks: vec![DoctorCheck {
                    id: "deployment.layout".to_owned(),
                    status: "missing".to_owned(),
                    message: Some("target path does not exist".to_owned()),
                    next_affordance: Some(
                        "specify a valid reference deployment directory initialized with fss"
                            .to_owned(),
                    ),
                    fields: BTreeMap::new(),
                }],
            };
        }
    };

    if !root_meta.is_dir() {
        return DoctorReport {
            schema: "fss.doctor.v1".to_owned(),
            version: VERSION.to_owned(),
            root: Some(root.to_path_buf()),
            verdict: DoctorVerdict::NotADeployment,
            checks: vec![DoctorCheck {
                id: "deployment.layout".to_owned(),
                status: "missing".to_owned(),
                message: Some("target path is not a directory".to_owned()),
                next_affordance: Some(
                    "specify a valid reference deployment directory initialized with fss"
                        .to_owned(),
                ),
                fields: BTreeMap::new(),
            }],
        };
    }

    let layout_path = root.join(DEPLOYMENT_LAYOUT_FILENAME);
    let layout_meta = match fs::symlink_metadata(&layout_path) {
        Ok(m) => m,
        Err(e) => {
            if e.kind() == io::ErrorKind::PermissionDenied {
                return DoctorReport {
                    schema: "fss.doctor.v1".to_owned(),
                    version: VERSION.to_owned(),
                    root: Some(root.to_path_buf()),
                    verdict: DoctorVerdict::Unreadable,
                    checks: vec![DoctorCheck {
                        id: "deployment.access".to_owned(),
                        status: "unreadable".to_owned(),
                        message: Some("permission denied reading LAYOUT file".to_owned()),
                        next_affordance: Some(
                            "verify filesystem permissions for LAYOUT file".to_owned(),
                        ),
                        fields: BTreeMap::new(),
                    }],
                };
            }
            return DoctorReport {
                schema: "fss.doctor.v1".to_owned(),
                version: VERSION.to_owned(),
                root: Some(root.to_path_buf()),
                verdict: DoctorVerdict::NotADeployment,
                checks: vec![DoctorCheck {
                    id: "deployment.layout".to_owned(),
                    status: "missing".to_owned(),
                    message: Some("missing LAYOUT file".to_owned()),
                    next_affordance: Some(
                        "initialize deployment layout using fss reference deployment".to_owned(),
                    ),
                    fields: BTreeMap::new(),
                }],
            };
        }
    };

    if !layout_meta.is_file() {
        return DoctorReport {
            schema: "fss.doctor.v1".to_owned(),
            version: VERSION.to_owned(),
            root: Some(root.to_path_buf()),
            verdict: DoctorVerdict::NotADeployment,
            checks: vec![DoctorCheck {
                id: "deployment.layout".to_owned(),
                status: "missing".to_owned(),
                message: Some("LAYOUT is not a regular file".to_owned()),
                next_affordance: Some(
                    "initialize deployment layout using fss reference deployment".to_owned(),
                ),
                fields: BTreeMap::new(),
            }],
        };
    }

    let layout_text = match fs::read_to_string(&layout_path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            return DoctorReport {
                schema: "fss.doctor.v1".to_owned(),
                version: VERSION.to_owned(),
                root: Some(root.to_path_buf()),
                verdict: DoctorVerdict::Unreadable,
                checks: vec![DoctorCheck {
                    id: "deployment.access".to_owned(),
                    status: "unreadable".to_owned(),
                    message: Some("permission denied reading LAYOUT file".to_owned()),
                    next_affordance: Some(
                        "verify filesystem permissions for LAYOUT file".to_owned(),
                    ),
                    fields: BTreeMap::new(),
                }],
            };
        }
        Err(e) => {
            return DoctorReport {
                schema: "fss.doctor.v1".to_owned(),
                version: VERSION.to_owned(),
                root: Some(root.to_path_buf()),
                verdict: DoctorVerdict::AttentionRequired,
                checks: vec![DoctorCheck {
                    id: "deployment.layout".to_owned(),
                    status: "corrupt".to_owned(),
                    message: Some(format!("failed to read LAYOUT file: {e}")),
                    next_affordance: Some("restore LAYOUT file from backup or recreate".to_owned()),
                    fields: BTreeMap::new(),
                }],
            };
        }
    };

    let layout = match DeploymentLayout::parse_canonical_text(&layout_text) {
        Ok(l) => l,
        Err(e) => {
            return DoctorReport {
                schema: "fss.doctor.v1".to_owned(),
                version: VERSION.to_owned(),
                root: Some(root.to_path_buf()),
                verdict: DoctorVerdict::AttentionRequired,
                checks: vec![DoctorCheck {
                    id: "deployment.layout".to_owned(),
                    status: "corrupt".to_owned(),
                    message: Some(format!("failed to parse LAYOUT file: {e}")),
                    next_affordance: Some("repair or rewrite canonical LAYOUT file".to_owned()),
                    fields: BTreeMap::new(),
                }],
            };
        }
    };

    let objects_dir = root.join(&layout.objects_relpath);
    let ledger_file = root.join(&layout.ledger_relpath);
    let effects_file = root.join(&layout.effects_relpath);

    // 1. Layout check
    let mut layout_check = DoctorCheck::new("deployment.layout", "clean");
    let has_objects = objects_dir.is_dir();
    let has_ledger_parent = ledger_file.parent().is_some_and(Path::is_dir);
    let has_effects_parent = effects_file.parent().is_some_and(Path::is_dir);
    if !has_objects || !has_ledger_parent || !has_effects_parent {
        layout_check.status = "incomplete".to_owned();
        layout_check.message = Some("missing expected deployment subdirectories".to_owned());
        layout_check.next_affordance = Some("restore missing deployment subdirectories".to_owned());
    }

    // 2. Writer detection
    let lock_paths = vec![
        objects_dir.join("LOCK"),
        objects_dir.join("spool").join("LOCK"),
        ledger_file.clone(),
        effects_file.clone(),
    ];
    let writer_state = detect_writers(
        &HostSpoolIo,
        &lock_paths,
        Some(&HostLockTableSource),
        WriterDetectionOptions::default(),
    );
    let writer_held = writer_state.is_held();
    let mut writer_check = DoctorCheck::new(
        "deployment.writer",
        if writer_held {
            "concurrent_writer"
        } else {
            "clean"
        },
    );
    if writer_held {
        writer_check.fields.insert(
            "writer_state".to_owned(),
            DoctorValue::String("held".to_owned()),
        );
        writer_check
            .fields
            .insert("possibly_stale".to_owned(), DoctorValue::Bool(true));
        if let WriterState::Held {
            pid_hint: Some(pid),
            ..
        } = writer_state
        {
            writer_check
                .fields
                .insert("pid_hint".to_owned(), DoctorValue::Number(i64::from(pid)));
        }
        writer_check.message =
            Some("concurrent writer detected holding deployment lock".to_owned());
        writer_check.next_affordance =
            Some("wait for writer to complete or terminate holding process".to_owned());
    } else {
        writer_check.fields.insert(
            "writer_state".to_owned(),
            DoctorValue::String("not_held".to_owned()),
        );
    }

    // 3. Ledger journal check
    let mut ledger_check = DoctorCheck::new("ledger.journal", "clean");
    if !ledger_file.exists() {
        ledger_check.status = "absent".to_owned();
        ledger_check.message = Some("ledger journal file does not exist".to_owned());
    } else {
        let max_bytes = 64 * 1024 * 1024;
        match doctor_bounded(&ledger_file, max_bytes) {
            Ok(doc_report) => {
                ledger_check.fields.insert(
                    "records_count".to_owned(),
                    DoctorValue::Number(doc_report.records_count() as i64),
                );
                ledger_check.fields.insert(
                    "committed_len".to_owned(),
                    DoctorValue::Number(doc_report.committed_len() as i64),
                );

                if let Some(foreign) = doc_report.foreign_range() {
                    let journal_bytes = match fs::read(&ledger_file) {
                        Ok(b) => b,
                        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                            return DoctorReport {
                                schema: "fss.doctor.v1".to_owned(),
                                version: VERSION.to_owned(),
                                root: Some(root.to_path_buf()),
                                verdict: DoctorVerdict::Unreadable,
                                checks: vec![DoctorCheck {
                                    id: "deployment.access".to_owned(),
                                    status: "unreadable".to_owned(),
                                    message: Some(format!("failed to read ledger journal: {e}")),
                                    next_affordance: Some(
                                        "verify filesystem permissions for ledger journal"
                                            .to_owned(),
                                    ),
                                    fields: BTreeMap::new(),
                                }],
                            };
                        }
                        Err(e) => {
                            ledger_check.status = "corrupt".to_owned();
                            ledger_check.message =
                                Some(format!("failed to read ledger journal bytes: {e}"));
                            Vec::new()
                        }
                    };

                    if !journal_bytes.is_empty() {
                        if let Some(offset) = find_structurally_valid_record(
                            &journal_bytes,
                            foreign.offset(),
                            foreign.length(),
                        ) {
                            ledger_check.status = "corrupt_history".to_owned();
                            ledger_check.fields.insert(
                                "foreign_offset".to_owned(),
                                DoctorValue::Number(foreign.offset() as i64),
                            );
                            ledger_check.fields.insert(
                                "foreign_length".to_owned(),
                                DoctorValue::Number(foreign.length() as i64),
                            );
                            ledger_check.fields.insert(
                                "valid_record_offset".to_owned(),
                                DoctorValue::Number(offset as i64),
                            );
                            ledger_check.message = Some(format!(
                                "corrupt history: valid record found in foreign trailing bytes at offset {offset}"
                            ));
                            ledger_check.next_affordance = Some(
                                "owner action: restore from backup or inspect physical media"
                                    .to_owned(),
                            );
                        } else {
                            ledger_check.status = "foreign_trailing_bytes".to_owned();
                            ledger_check.fields.insert(
                                "foreign_offset".to_owned(),
                                DoctorValue::Number(foreign.offset() as i64),
                            );
                            ledger_check.fields.insert(
                                "foreign_length".to_owned(),
                                DoctorValue::Number(foreign.length() as i64),
                            );
                            let plan_digest = match doc_report.plan(&ledger_file) {
                                Ok(p) => p.plan_digest().to_string(),
                                Err(_) => String::new(),
                            };
                            ledger_check.fields.insert(
                                "plan_digest".to_owned(),
                                DoctorValue::String(plan_digest.clone()),
                            );
                            ledger_check.message = Some(
                                "foreign trailing bytes detected after committed records"
                                    .to_owned(),
                            );
                            ledger_check.next_affordance = Some(format!(
                                "fss-lab recover --root {} --plan-ledger-repair then --apply-ledger-repair {}",
                                root.display(),
                                plan_digest
                            ));
                        }
                    }
                } else if let Some(incomplete_tail) = doc_report.incomplete_tail() {
                    ledger_check.fields.insert(
                        "incomplete_tail_offset".to_owned(),
                        DoctorValue::Number(incomplete_tail as i64),
                    );
                    if writer_held {
                        ledger_check.status = "possibly_in_flight".to_owned();
                        ledger_check
                            .fields
                            .insert("possibly_in_flight".to_owned(), DoctorValue::Bool(true));
                        ledger_check.message = Some(
                            "incomplete tail observed while concurrent writer is held".to_owned(),
                        );
                        ledger_check.next_affordance =
                            Some("wait for writer to complete in-flight append".to_owned());
                    } else {
                        ledger_check.status = "incomplete_tail".to_owned();
                        ledger_check.message =
                            Some("incomplete record tail detected at end of journal".to_owned());
                        ledger_check.next_affordance = Some(format!(
                            "fss-lab recover --root {} --truncate-incomplete-tail ledger",
                            root.display()
                        ));
                    }
                }
            }
            Err(e) => {
                ledger_check.status = "corrupt".to_owned();
                ledger_check.message = Some(format!("failed to inspect ledger journal: {e}"));
                ledger_check.next_affordance =
                    Some("owner action: restore from backup or inspect physical media".to_owned());
            }
        }
    }

    // 4. Effects journal check and 5. Obligations check
    let mut effects_check = DoctorCheck::new("effects.journal", "clean");
    let mut obligations_check = DoctorCheck::new("effects.obligations", "clean");

    if !effects_file.exists() {
        effects_check.status = "absent".to_owned();
        effects_check.message = Some("effects journal file does not exist".to_owned());
        obligations_check.status = "absent".to_owned();
    } else {
        match DurableEffectJournal::inspect(&effects_file, DurableLedgerLimits::default()) {
            Ok(eff_report) => {
                if let Some(foreign) = eff_report.foreign_range {
                    let eff_bytes = match fs::read(&effects_file) {
                        Ok(b) => b,
                        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                            return DoctorReport {
                                schema: "fss.doctor.v1".to_owned(),
                                version: VERSION.to_owned(),
                                root: Some(root.to_path_buf()),
                                verdict: DoctorVerdict::Unreadable,
                                checks: vec![DoctorCheck {
                                    id: "deployment.access".to_owned(),
                                    status: "unreadable".to_owned(),
                                    message: Some(format!("failed to read effects journal: {e}")),
                                    next_affordance: Some(
                                        "verify filesystem permissions for effects journal"
                                            .to_owned(),
                                    ),
                                    fields: BTreeMap::new(),
                                }],
                            };
                        }
                        Err(_) => Vec::new(),
                    };

                    if !eff_bytes.is_empty() {
                        if let Some(offset) = find_structurally_valid_record(
                            &eff_bytes,
                            foreign.offset(),
                            foreign.length(),
                        ) {
                            effects_check.status = "corrupt_history".to_owned();
                            effects_check.fields.insert(
                                "foreign_offset".to_owned(),
                                DoctorValue::Number(foreign.offset() as i64),
                            );
                            effects_check.fields.insert(
                                "foreign_length".to_owned(),
                                DoctorValue::Number(foreign.length() as i64),
                            );
                            effects_check.fields.insert(
                                "valid_record_offset".to_owned(),
                                DoctorValue::Number(offset as i64),
                            );
                            effects_check.message = Some(format!(
                                "corrupt history: valid record found in foreign trailing bytes at offset {offset}"
                            ));
                            effects_check.next_affordance = Some(
                                "owner action: restore from backup or inspect physical media"
                                    .to_owned(),
                            );
                        } else {
                            effects_check.status = "foreign_trailing_bytes".to_owned();
                            effects_check.fields.insert(
                                "foreign_offset".to_owned(),
                                DoctorValue::Number(foreign.offset() as i64),
                            );
                            effects_check.fields.insert(
                                "foreign_length".to_owned(),
                                DoctorValue::Number(foreign.length() as i64),
                            );
                            let plan_digest = match fss_ledger::doctor(&eff_bytes)
                                .and_then(|r| r.plan(&effects_file))
                            {
                                Ok(p) => p.plan_digest().to_string(),
                                Err(_) => String::new(),
                            };
                            effects_check.fields.insert(
                                "plan_digest".to_owned(),
                                DoctorValue::String(plan_digest.clone()),
                            );
                            effects_check.message = Some(
                                "foreign trailing bytes detected after committed records"
                                    .to_owned(),
                            );
                            effects_check.next_affordance = Some(format!(
                                "fss-lab recover --root {} --plan-effect-repair then --apply-effect-repair {}",
                                root.display(),
                                plan_digest
                            ));
                        }
                    }
                } else if let Some(incomplete_tail) = eff_report.incomplete_tail {
                    effects_check.fields.insert(
                        "incomplete_tail_offset".to_owned(),
                        DoctorValue::Number(incomplete_tail as i64),
                    );
                    if writer_held {
                        effects_check.status = "possibly_in_flight".to_owned();
                        effects_check
                            .fields
                            .insert("possibly_in_flight".to_owned(), DoctorValue::Bool(true));
                        effects_check.message = Some(
                            "incomplete tail observed while concurrent writer is held".to_owned(),
                        );
                        effects_check.next_affordance =
                            Some("wait for writer to complete in-flight append".to_owned());
                    } else {
                        effects_check.status = "incomplete_tail".to_owned();
                        effects_check.message = Some(
                            "incomplete record tail detected at end of effects journal".to_owned(),
                        );
                        effects_check.next_affordance = Some(format!(
                            "fss-lab recover --root {} --truncate-incomplete-tail effects",
                            root.display()
                        ));
                    }
                }

                // Check obligations
                if !eff_report.indeterminate_operations.is_empty() {
                    obligations_check.status = "indeterminate_obligations".to_owned();
                    obligations_check.fields.insert(
                        "indeterminate_count".to_owned(),
                        DoctorValue::Number(eff_report.indeterminate_operations.len() as i64),
                    );
                    let ops: Vec<String> = eff_report
                        .indeterminate_operations
                        .iter()
                        .map(|op| op.operation_id.to_string())
                        .collect();
                    obligations_check.fields.insert(
                        "indeterminate_operations".to_owned(),
                        DoctorValue::StringList(ops),
                    );
                    obligations_check.message = Some(format!(
                        "{} indeterminate effect obligation(s) require reconciliation",
                        eff_report.indeterminate_operations.len()
                    ));
                    obligations_check.next_affordance = Some(format!(
                        "fss-lab recover --root {} --reconcile-effects",
                        root.display()
                    ));
                } else {
                    obligations_check.fields.insert(
                        "total_obligations".to_owned(),
                        DoctorValue::Number(eff_report.obligation_counts.total as i64),
                    );
                }
            }
            Err(e) => {
                effects_check.status = "corrupt".to_owned();
                effects_check.message = Some(format!("failed to inspect effects journal: {e}"));
                obligations_check.status = "unknown".to_owned();
            }
        }
    }

    // 6. Publication staging and 7. Roots check
    let mut staging_check = DoctorCheck::new("publication.staging", "clean");
    let mut roots_check = DoctorCheck::new("publication.roots", "clean");

    let limits: LocalPublicationLimits = DeploymentLimits::default().to_publication_limits();
    let local_inspection = inspect_with_ledger_journal(
        &HostSpoolIo,
        &objects_dir,
        Some(&ledger_file),
        limits,
        Some(&HostLockTableSource),
        WriterDetectionOptions::default(),
    );

    match local_inspection {
        Ok(local) => {
            // Check staging
            if !local.report.spool.orphaned_staging.is_empty() {
                staging_check.status = "orphaned_staging".to_owned();
                staging_check.fields.insert(
                    "orphaned_count".to_owned(),
                    DoctorValue::Number(local.report.spool.orphaned_staging.len() as i64),
                );
                staging_check.message = Some(format!(
                    "{} orphaned staging file(s) found in spool",
                    local.report.spool.orphaned_staging.len()
                ));
                staging_check.next_affordance = Some(format!(
                    "fss-lab recover --root {} --discard-orphaned-staging",
                    root.display()
                ));
            }

            // Check roots
            if !local.broken_slots.is_empty() {
                roots_check.status = "broken_roots".to_owned();
                let broken: Vec<String> = local
                    .broken_slots
                    .iter()
                    .map(|k| k.as_str().to_owned())
                    .collect();
                roots_check
                    .fields
                    .insert("broken_slots".to_owned(), DoctorValue::StringList(broken));
                roots_check.message = Some(format!(
                    "{} broken publication slot(s) detected",
                    local.broken_slots.len()
                ));
                roots_check.next_affordance = Some(
                    "owner action: inspect physical storage or restore damaged slot files"
                        .to_owned(),
                );
            } else if !local.report.orphaned_temps.is_empty() || !local.redundant_temps.is_empty() {
                let total_temps = local.report.orphaned_temps.len() + local.redundant_temps.len();
                roots_check.status = "orphaned_root_temps".to_owned();
                roots_check.fields.insert(
                    "orphaned_temp_count".to_owned(),
                    DoctorValue::Number(total_temps as i64),
                );
                roots_check.message = Some(format!(
                    "{total_temps} orphaned root temporary file(s) found"
                ));
                roots_check.next_affordance = Some(format!(
                    "fss-lab recover --root {} --discard-orphaned-temps",
                    root.display()
                ));
            } else if let Ok(ledger_insp) = fss_ledger::inspect_durable(
                &ledger_file,
                &layout.site_lineage,
                DurableLedgerLimits::default(),
            ) {
                let linkage = inspect_linkage(&local, &ledger_insp);
                if !linkage.pending.is_empty() {
                    roots_check.status = "pending_roots".to_owned();
                    roots_check.fields.insert(
                        "pending_count".to_owned(),
                        DoctorValue::Number(linkage.pending.len() as i64),
                    );
                    let pending_slots: Vec<String> = linkage
                        .pending
                        .iter()
                        .map(|p| p.slot.as_str().to_owned())
                        .collect();
                    roots_check.fields.insert(
                        "pending_slots".to_owned(),
                        DoctorValue::StringList(pending_slots),
                    );
                    roots_check.message = Some(format!(
                        "{} publication root(s) pending ledger commit",
                        linkage.pending.len()
                    ));
                    roots_check.next_affordance =
                        Some("rerun producing command or explicit commit".to_owned());
                }
            }
        }
        Err(e) => {
            staging_check.status = "unreadable".to_owned();
            staging_check.message = Some(format!("failed to inspect publication objects: {e}"));
            roots_check.status = "unreadable".to_owned();
        }
    }

    // 8. Sidecar cleanup check
    let mut sidecars_check = DoctorCheck::new("sidecars", "clean");
    let mut leftover_temps = Vec::new();
    let mut quarantine_files = Vec::new();

    let scan_dir = |dir: &Path, leftovers: &mut Vec<String>, quarantines: &mut Vec<String>| {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.ends_with(".quarantine") {
                    quarantines.push(name.clone());
                }
                if name.contains(".tmp.") {
                    leftovers.push(name);
                }
            }
        }
    };

    scan_dir(
        &root.join("ledger"),
        &mut leftover_temps,
        &mut quarantine_files,
    );
    scan_dir(
        &root.join("effects"),
        &mut leftover_temps,
        &mut quarantine_files,
    );
    leftover_temps.sort();
    quarantine_files.sort();

    if !leftover_temps.is_empty() {
        sidecars_check.status = "leftover_repair_temps".to_owned();
        sidecars_check.fields.insert(
            "leftover_temps".to_owned(),
            DoctorValue::StringList(leftover_temps),
        );
        sidecars_check.message =
            Some("leftover temporary files from interrupted repair detected".to_owned());
        sidecars_check.next_affordance = Some(format!(
            "fss-lab recover --root {} --apply-ledger-repair",
            root.display()
        ));
    } else if !quarantine_files.is_empty() {
        sidecars_check.fields.insert(
            "quarantine_files".to_owned(),
            DoctorValue::StringList(quarantine_files),
        );
    }

    let checks = vec![
        layout_check,
        writer_check,
        ledger_check,
        effects_check,
        obligations_check,
        staging_check,
        roots_check,
        sidecars_check,
    ];

    let verdict = if checks.iter().all(|c| c.status == "clean") {
        DoctorVerdict::Healthy
    } else {
        DoctorVerdict::AttentionRequired
    };

    DoctorReport {
        schema: "fss.doctor.v1".to_owned(),
        version: VERSION.to_owned(),
        root: Some(root.to_path_buf()),
        verdict,
        checks,
    }
}
