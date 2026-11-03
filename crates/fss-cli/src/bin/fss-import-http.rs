#![forbid(unsafe_code)]
//! Exact, owner-approved conversion of retained HTTP originals into a recording import.

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use fss_cli::ExitIdentity;
use fss_cli::agent_json::{object, string};
use fss_codec_mjpeg::DecodeBudget;
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId};
use fss_geometry::WorkBudget;
use fss_object::{MAX_MANIFEST_CHILDREN, SpoolLimits};
use fss_publication::{LocalPublicationLimits, LocalRootPublisher};
use fss_reference::ingest::http_import::{HttpImportAuthority, HttpImportRequest, import_http};
use fss_reference::{ReferenceDeployment, ReplayCx};

#[path = "fss-import-http/plan.rs"]
mod plan;
use plan::{FORMAT, Options};

const CAPS: [&str; 4] = [
    "CAP-READ-MEDIA-001",
    "CAP-OBJECT-STAGE-001",
    "CAP-OBJECT-PUBLISH-001",
    "CAP-RETENTION-COMMIT-001",
];
const HELP: &str = "fss-import-http --archive EXISTING_ABSOLUTE_ARCHIVE --root ABSOLUTE_DEPLOYMENT --site SITE\n\
  --source sha256:HEX --generation N --receive-clock sha256:HEX --retention-evidence sha256:HEX\n\
  --head sha256:HEX --reads N --bytes N --sensor-id ID --stream-id ID --receive-time-ns N\n\
  --owner-authorized yes --read-originals yes --retain-originals yes [--approve sha256:PLAN]\n\
  Optional timing: --capture-start-ns N --capture-uncertainty-ns N --fps F (all three required).\n\
  Bounds: --max-frames 128 --max-source-bytes 67108864 --max-work 1000000000000\n\
          --max-framing-work 10000000000 --timeout-ms 30000. Optional --principal ID.\n\
  Without --approve: prints an exact plan without filesystem, clock or network I/O.\n\
  Replay selects ALL complete JPEGs from the exact pinned prefix; exceeded bounds refuse.\n\
  Original HTTP headers, wrappers and partial tail are copied into the recording custody.\n\
  The ordered JPEG stream is reconstructed media. No source EOF or capture clock is invented.\n\
  Native retained decode, inference and fss-event watch consume the returned import identity.\n\
  Existing destination sensor privacy masks apply when decoding. No pixels are printed.\n\
  Source and destination must be distinct, non-nested stores. Originals remain local unencrypted.\n\
  Existing publisher locks/recovery sync apply; archive opening is not forensic read-only.\n";

struct Owner<'a> {
    options: &'a Options,
    cx: &'a ReplayCx,
    authority: &'a ContextAuthority,
    start: Instant,
}
impl HttpImportAuthority for Owner<'_> {
    fn permit(&self, request: &HttpImportRequest, destination: &ReferenceDeployment) -> bool {
        self.options.request.digest().ok() == request.digest().ok()
            && destination.root() == self.options.root
            && destination.site_lineage() == self.options.site
            && self.cx.checkpoint("import_http:operator").is_ok()
            && self.authority.cancellation_reason.is_none()
            && CAPS.iter().all(|c| self.authority.has_capability(c))
            && self.start.elapsed() < Duration::from_millis(self.options.timeout_ms)
    }
}
fn existing_directory(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_dir())
}
fn execute(options: &Options) -> Result<String, &'static str> {
    // Exact approval precedes all filesystem and clock use, including context construction.
    let approval = options.approval()?;
    if options.approve != Some(approval) {
        return Err("ERR-HTTP-IMPORT-APPROVAL-001");
    }
    let mut capabilities: Vec<_> = CAPS.iter().map(|c| (*c).to_owned()).collect();
    capabilities.push("ADP-REPLAY-001".into());
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:http-import".into(),
        operation_id: OperationId::parse("operation:http-import")
            .map_err(|_| fss_cli::ERR_CLI_RUNTIME_FAILURE)?,
        principal: options.principal.clone(),
        capabilities,
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(1024 * 1024 * 1024)
            .storage_operations(1_000_000)
            .build()
            .map_err(|_| fss_cli::ERR_CLI_RUNTIME_FAILURE)?,
        privacy_scope: "privacy:owner-original-http-custody".into(),
        retention_scope: "retention:source-closed-http-import".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })
    .map_err(|_| fss_cli::ERR_CLI_RUNTIME_FAILURE)?;
    authority
        .validate()
        .map_err(|_| fss_cli::ERR_CLI_RUNTIME_FAILURE)?;
    let start = Instant::now();
    for name in ["", "spool", "roots", "tombstones"] {
        if !existing_directory(&options.archive.join(name)) {
            return Err("ERR-HTTP-IMPORT-SOURCE-001");
        }
    }
    let source = options
        .archive
        .canonicalize()
        .map_err(|_| "ERR-HTTP-IMPORT-SOURCE-001")?;
    let target = match std::fs::symlink_metadata(&options.root) {
        Ok(m) if m.file_type().is_dir() => options
            .root
            .canonicalize()
            .map_err(|_| "ERR-HTTP-IMPORT-REQUEST-001")?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => options
            .root
            .parent()
            .ok_or("ERR-HTTP-IMPORT-REQUEST-001")?
            .canonicalize()
            .map_err(|_| "ERR-HTTP-IMPORT-REQUEST-001")?
            .join(
                options
                    .root
                    .file_name()
                    .ok_or("ERR-HTTP-IMPORT-REQUEST-001")?,
            ),
        _ => return Err("ERR-HTTP-IMPORT-REQUEST-001"),
    };
    if source.starts_with(&target) || target.starts_with(&source) {
        return Err("ERR-HTTP-IMPORT-REQUEST-001");
    }
    let cx = ReplayCx::from_context_authority(&authority, options.root.clone())
        .map_err(|_| "ERR-HTTP-IMPORT-AUTHORITY-001")?;
    let owner = Owner {
        options,
        cx: &cx,
        authority: &authority,
        start,
    };
    if start.elapsed() >= Duration::from_millis(options.timeout_ms) {
        return Err("ERR-HTTP-IMPORT-AUTHORITY-001");
    }
    let source = LocalRootPublisher::open(
        &options.archive,
        LocalPublicationLimits::new(
            65536,
            MAX_MANIFEST_CHILDREN,
            65536,
            65536,
            SpoolLimits::new(65536, 1024 * 1024 * 1024, 16 * 1024 * 1024, 131072),
        ),
    )
    .map_err(|_| "ERR-HTTP-IMPORT-SOURCE-001")?;
    cx.checkpoint("import_http:destination")
        .map_err(|_| "ERR-HTTP-IMPORT-AUTHORITY-001")?;
    if start.elapsed() >= Duration::from_millis(options.timeout_ms) {
        return Err("ERR-HTTP-IMPORT-AUTHORITY-001");
    }
    let mut destination = ReferenceDeployment::open(&options.root, &options.site, &cx)
        .map_err(|_| "ERR-HTTP-IMPORT-CUSTODY-001")?;
    let mut work = WorkBudget::new(options.work);
    let mut framing = DecodeBudget::new(options.framing);
    let receipt = import_http(
        &source,
        &mut destination,
        &options.request,
        &owner,
        &cx,
        &mut work,
        &mut framing,
    )
    .map_err(|e| e.stable_id())?;
    Ok(object(&[
        ("format", string(FORMAT)),
        ("kind", string("imported")),
        (
            "import_identity",
            string(&receipt.import_identity.to_text()),
        ),
        ("import_root", string(&receipt.import_root.to_text())),
        (
            "manifest_digest",
            string(&receipt.manifest_digest.to_text()),
        ),
        ("origin_proof", string(&receipt.proof.to_text())),
        ("frames", receipt.frames.to_string()),
        ("source_ending", string(receipt.ending.as_str())),
        ("capture_time_label", string(receipt.capture_time_label)),
        ("reused", receipt.reused.to_string()),
        (
            "original_bytes_retained",
            options.request.pin.bytes.to_string(),
        ),
        ("source_archive_retained_separately", "true".into()),
        ("network", string("none")),
        ("work_used", work.used().to_string()),
    ]))
}
fn emit(text: &str) -> io::Result<()> {
    if text.len() > 16 * 1024 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut out = io::stdout().lock();
    let line = format!("{text}\n");
    let mut bytes = line.as_bytes();
    let mut interrupted = 0;
    while !bytes.is_empty() {
        match out.write(&bytes[..bytes.len().min(4096)]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) if n <= bytes.len().min(4096) => {
                bytes = &bytes[n..];
                interrupted = 0;
            }
            Ok(_) => return Err(io::ErrorKind::InvalidData.into()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted && interrupted < 7 => interrupted += 1,
            Err(e) => return Err(e),
        }
    }
    out.flush()
}
fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).take(65).collect();
    if args.len() == 1 && matches!(args[0].to_str(), Some("--help" | "help")) {
        return ExitCode::from(if emit(HELP).is_ok() {
            ExitIdentity::SUCCESS.code
        } else {
            ExitIdentity::RUNTIME_FAILURE.code
        });
    }
    let options = match Options::parse(&args) {
        Ok(options) => options,
        Err(reason) => {
            eprintln!("ERR-CLI-MALFORMED-VALUE-001: {reason}. Use fss-import-http --help.");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    let result = if options.approve.is_none() {
        options.preview()
    } else {
        execute(&options)
    };
    match result {
        Ok(report) if emit(&report).is_ok() => ExitCode::from(ExitIdentity::SUCCESS.code),
        Ok(_) => {
            eprintln!(
                "ERR-CLI-RUNTIME-FAILURE-001: output failed; an approved import may already be durable. Retry the exact plan to reconcile."
            );
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
        Err(code) => {
            eprintln!(
                "{code}: import not confirmed by this attempt; retain the exact plan for reconciliation."
            );
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args() -> Vec<OsString> {
        let sha = ContentDigest::sha256(b"fixture").to_text();
        [
            "--archive",
            "/absent-http-import-fixture/source",
            "--root",
            "/absent-http-import-fixture/destination",
            "--site",
            "site:test",
            "--source",
            &sha,
            "--generation",
            "1",
            "--receive-clock",
            &sha,
            "--retention-evidence",
            &sha,
            "--head",
            &sha,
            "--reads",
            "1",
            "--bytes",
            "100",
            "--sensor-id",
            "sensor:test",
            "--stream-id",
            "stream:test",
            "--receive-time-ns",
            "2000000000",
            "--owner-authorized",
            "yes",
            "--read-originals",
            "yes",
            "--retain-originals",
            "yes",
        ]
        .iter()
        .map(OsString::from)
        .collect()
    }
    #[test]
    fn preview_is_pure_and_approval_binds_destination_sensor_and_time() -> Result<(), &'static str>
    {
        let original = Options::parse(&args())?;
        let approval = original.approval()?;
        assert!(original.preview()?.contains("\"writes\":\"none\""));
        for (key, value) in [
            ("--root", "/absent-http-import-fixture/other"),
            ("--sensor-id", "sensor:other"),
            ("--receive-time-ns", "3000000000"),
        ] {
            let mut changed = args();
            let position = changed
                .iter()
                .position(|s| s == key)
                .ok_or("fixture option")?;
            changed[position + 1] = value.into();
            let mut changed = Options::parse(&changed)?;
            assert_ne!(changed.approval()?, approval);
            changed.approve = Some(approval);
            assert_eq!(
                execute(&changed).err(),
                Some("ERR-HTTP-IMPORT-APPROVAL-001")
            );
        }
        Ok(())
    }
    #[test]
    fn independent_original_permissions_and_complete_timing_are_required()
    -> Result<(), &'static str> {
        for key in ["--read-originals", "--retain-originals"] {
            let mut changed = args();
            let position = changed
                .iter()
                .position(|s| s == key)
                .ok_or("fixture option")?;
            changed[position + 1] = "no".into();
            assert!(Options::parse(&changed).is_err());
        }
        let mut changed = args();
        changed.extend([OsString::from("--fps"), OsString::from("30")]);
        assert!(Options::parse(&changed).is_err());
        Ok(())
    }
}
